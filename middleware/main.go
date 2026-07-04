package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"

	pg_query "github.com/pganalyze/pg_query_go/v6"
)

// ----------------------------------------------------------------------------------
// Types
// ----------------------------------------------------------------------------------

type ColumnSecurity struct {
	Encrypt    bool
	Mode       string
	BlindIndex string
}

type TableMetadata struct {
	Columns map[string]ColumnSecurity
}

type BlindIndexGen struct {
	SourceIndex int
}

type StatementMetaData struct {
	Table               string
	Columns             []string
	InsertBlindIndexes  []BlindIndexGen
	SelectBlindIndexMap map[int]string
	FilterColName       string
	FilterParamIndex    int
}

type FilterContext struct {
	ColName string
	Value   string
}


type PgParser struct {
	statements map[string]StatementMetaData
	database   string
}

type DecryptTarget struct {
	ColIndex  int
	TableName string
}

type BufferedMsg struct {
	Type    byte
	Payload []byte
}

type Session struct {
	clientConn net.Conn
	dbConn     net.Conn
	parser     *PgParser

	intercepting   bool
	decryptTargets []DecryptTarget

	filterColName  string
	filterColIndex int    
	filterValue    string
	rowsSent       int32  
}

// ----------------------------------------------------------------------------------
// Globals
// ----------------------------------------------------------------------------------

var (
	masterDEK      []byte
	cacheMu        sync.RWMutex
	metadataCache  = make(map[string]TableMetadata)    
	tableOIDsCache = make(map[string]map[int32]string) 
)

var (
	backendHost = envOr("GATEWAY_DB_HOST", "127.0.0.1")
	backendPort = envOr("GATEWAY_DB_PORT", "5433")
)

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func init() {

}

// ----------------------------------------------------------------------------------
// main
// ----------------------------------------------------------------------------------

func main() {
	certFile := envOr("GATEWAY_CERT", "../certs/server.crt")
	keyFile := envOr("GATEWAY_KEY", "../certs/server.key")

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatal("Erro certificado: ", err)
	}
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}

	var errKey error
	masterDEK, errKey = fetchOrGenerateMasterKey()
	if errKey != nil {
		log.Printf("[Init] Aviso: Nao foi possivel obter a chave do Vault. Gerando chave local em memoria.")
		masterDEK = make([]byte, 32)
		io.ReadFull(rand.Reader, masterDEK)
	}

	addr := ":" + envOr("GATEWAY_LISTEN_PORT", "8000")
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()

	fmt.Printf("Gateway iniciado em %s â†’ %s:%s\n", addr, backendHost, backendPort)

	for {
		client, err := ln.Accept()
		if err != nil {
			continue
		}
		go handleConnection(client, tlsConfig)
	}
}

func handleConnection(client net.Conn, tlsConfig *tls.Config) {
	defer client.Close()

	buf := make([]byte, 8)
	if _, err := io.ReadFull(client, buf); err != nil {
		log.Println("Erro lendo header:", err)
		return
	}

	isSSLRequest :=
		buf[4] == 0x04 && buf[5] == 0xD2 &&
			buf[6] == 0x16 && buf[7] == 0x2F

	var finalClientConn net.Conn
	if isSSLRequest {
		client.Write([]byte{'S'})
		tlsConn := tls.Server(client, tlsConfig)
		if err := tlsConn.Handshake(); err != nil {
			return
		}
		log.Println("TLS estabelecido")
		finalClientConn = tlsConn
	} else {
		finalClientConn = client
	}


	var startupMsg []byte

	if isSSLRequest {
		header := make([]byte, 4)
		if _, err := io.ReadFull(finalClientConn, header); err != nil {
			return
		}
		sLen := int(binary.BigEndian.Uint32(header))
		if sLen < 8 || sLen > 10000 {
			return
		}
		body := make([]byte, sLen-4)
		if _, err := io.ReadFull(finalClientConn, body); err != nil {
			return
		}
		startupMsg = append(header, body...)
	} else {
		sLen := int(binary.BigEndian.Uint32(buf[:4]))
		if sLen < 8 || sLen > 10000 {
			return
		}
		if sLen > 8 {
			remaining := make([]byte, sLen-8)
			if _, err := io.ReadFull(finalClientConn, remaining); err != nil {
				return
			}
			startupMsg = append(buf, remaining...)
		} else {
			startupMsg = make([]byte, len(buf))
			copy(startupMsg, buf)
		}
	}


	params := parseStartupParams(startupMsg)
	database := params["database"]
	log.Printf("Conexao: user='%s' database='%s'", params["user"], database)


	dbConn, err := net.Dial("tcp", backendHost+":"+backendPort)
	if err != nil {
		log.Printf("Erro conectando ao backend: %v", err)
		return
	}
	defer dbConn.Close()

	if _, err := dbConn.Write(startupMsg); err != nil {
		return
	}

	readyPayload, err := relayAuth(finalClientConn, dbConn)
	if err != nil {
		log.Printf("Erro: %v", err)
		return
	}



	if err := loadAllMetadata(dbConn, database); err != nil {
		log.Printf("[Meta] Aviso: %v (proxy sem criptografia)", err)
	}

	writeWireMessage(finalClientConn, 'Z', readyPayload)

	log.Println("Autenticao completa, proxy iniciado")


	session := &Session{
		clientConn: finalClientConn,
		dbConn:     dbConn,
		parser: &PgParser{
			statements: make(map[string]StatementMetaData),
			database:   database,
		},
	}

	done := make(chan struct{}, 1)

	go func() {
		session.proxyDBToClient()
		done <- struct{}{}
	}()

	session.proxyClientToDB()

	<-done
}

func readWireMessage(conn net.Conn) (byte, []byte, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(conn, header); err != nil {
		return 0, nil, err
	}

	msgType := header[0]
	length := int(binary.BigEndian.Uint32(header[1:5]))

	if length <= 4 {
		return msgType, nil, nil
	}

	payload := make([]byte, length-4)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return 0, nil, err
	}

	return msgType, payload, nil
}

func writeWireMessage(conn net.Conn, msgType byte, payload []byte) error {
	length := uint32(len(payload) + 4)
	buf := make([]byte, 1+4+len(payload))
	buf[0] = msgType
	binary.BigEndian.PutUint32(buf[1:5], length)
	copy(buf[5:], payload)
	_, err := conn.Write(buf)
	return err
}

func sendSimpleQuery(conn net.Conn, query string) error {
	payload := append([]byte(query), 0)
	return writeWireMessage(conn, 'Q', payload)
}

func parseDataRow(payload []byte) []string {
	if len(payload) < 2 {
		return nil
	}
	numCols := int(binary.BigEndian.Uint16(payload[:2]))
	pos := 2
	values := make([]string, 0, numCols)

	for i := 0; i < numCols; i++ {
		if pos+4 > len(payload) {
			break
		}
		colLen := int(int32(binary.BigEndian.Uint32(payload[pos:])))
		pos += 4
		if colLen == -1 {
			values = append(values, "")
			continue
		}
		if pos+colLen > len(payload) {
			break
		}
		values = append(values, string(payload[pos:pos+colLen]))
		pos += colLen
	}
	return values
}

func parseDataRowBytes(payload []byte) [][]byte {
	if len(payload) < 2 {
		return nil
	}
	numCols := int(binary.BigEndian.Uint16(payload[:2]))
	pos := 2
	values := make([][]byte, 0, numCols)

	for i := 0; i < numCols; i++ {
		if pos+4 > len(payload) {
			break
		}
		colLen := int(int32(binary.BigEndian.Uint32(payload[pos:])))
		pos += 4
		if colLen == -1 {
			values = append(values, nil)
			continue
		}
		if pos+colLen > len(payload) {
			break
		}
		values = append(values, payload[pos:pos+colLen])
		pos += colLen
	}
	return values
}

func buildDataRow(values [][]byte) []byte {
	var buf bytes.Buffer
	numCols := uint16(len(values))
	binary.Write(&buf, binary.BigEndian, numCols)

	for _, val := range values {
		if val == nil {
			binary.Write(&buf, binary.BigEndian, int32(-1))
		} else {
			binary.Write(&buf, binary.BigEndian, int32(len(val)))
			buf.Write(val)
		}
	}
	return buf.Bytes()
}

func parseStartupParams(msg []byte) map[string]string {
	params := make(map[string]string)
	if len(msg) < 9 {
		return params
	}
	data := msg[8:]
	pos := 0
	for pos < len(data) {
		keyEnd := bytes.IndexByte(data[pos:], 0)
		if keyEnd <= 0 {
			break
		}
		key := string(data[pos : pos+keyEnd])
		pos += keyEnd + 1
		valEnd := bytes.IndexByte(data[pos:], 0)
		if valEnd < 0 {
			break
		}
		value := string(data[pos : pos+valEnd])
		pos += valEnd + 1
		params[key] = value
	}
	return params
}

func relayAuth(clientConn, dbConn net.Conn) ([]byte, error) {
	for {
		msgType, payload, err := readWireMessage(dbConn)
		if err != nil {
			return nil, fmt.Errorf("lendo do DB: %w", err)
		}

		switch msgType {
		case 'R': // Authentication
			writeWireMessage(clientConn, msgType, payload)

			if len(payload) >= 4 {
				authType := binary.BigEndian.Uint32(payload[:4])

				if authType == 3 || authType == 5 ||
					authType == 10 || authType == 11 {
					ct, cp, err := readWireMessage(clientConn)
					if err != nil {
						return nil, fmt.Errorf("lendo auth do cliente: %w", err)
					}
					writeWireMessage(dbConn, ct, cp)
				}
			}

		case 'Z': // ReadyForQuery
			return payload, nil

		case 'E': // Error
			writeWireMessage(clientConn, msgType, payload)
			return nil, fmt.Errorf("erro de autenticao do DB")

		default:

			writeWireMessage(clientConn, msgType, payload)
		}
	}
}

func loadAllMetadata(dbConn net.Conn, database string) error {
	query := `SELECT COALESCE(cls.oid, 0), c.table_name, c.column_name, COALESCE(d.description, '') ` +
		`FROM information_schema.columns c ` +
		`LEFT JOIN pg_class cls ON cls.relname = c.table_name ` +
		`LEFT JOIN pg_namespace ns ON ns.oid = cls.relnamespace AND ns.nspname = c.table_schema ` +
		`LEFT JOIN pg_description d ON d.objoid = cls.oid AND d.objsubid = c.ordinal_position ` +
		`WHERE c.table_schema = 'public'`

	if err := sendSimpleQuery(dbConn, query); err != nil {
		return fmt.Errorf("enviando query de metadados: %w", err)
	}

	results := make(map[string]*TableMetadata)

	for {
		mt, pl, err := readWireMessage(dbConn)
		if err != nil {
			return fmt.Errorf("lendo resposta de metadados: %w", err)
		}

		switch mt {
		case 'T': 
		case 'D': 
			vals := parseDataRow(pl)
			if len(vals) >= 4 {
				oidStr := vals[0]
				tableName := vals[1]
				columnName := vals[2]
				comment := vals[3]

				oidInt, _ := strconv.Atoi(oidStr)
				oid := int32(oidInt)

				cacheMu.Lock()
				if tableOIDsCache[database] == nil {
					tableOIDsCache[database] = make(map[int32]string)
				}
				tableOIDsCache[database][oid] = tableName
				cacheMu.Unlock()

				if _, ok := results[tableName]; !ok {
					results[tableName] = &TableMetadata{
						Columns: make(map[string]ColumnSecurity),
					}
				}

				info := ColumnSecurity{}
				if strings.Contains(comment, "gateway:encrypt") {
					info.Encrypt = true
					info.Mode = "aes-gcm"
				}

				parts := strings.Split(comment, " ")
				for _, p := range parts {
					if strings.HasPrefix(p, "gateway:blind_index=") {
						info.BlindIndex = strings.TrimPrefix(p, "gateway:blind_index=")
					}
				}

				results[tableName].Columns[columnName] = info
			}

		case 'C': 

		case 'E': 
			log.Printf("[Meta] Erro do PostgreSQL na query de metadados")

		case 'Z': 
			cacheMu.Lock()
			for table, meta := range results {
				key := database + "." + table
				metadataCache[key] = *meta
				for col, sec := range meta.Columns {
					if sec.Encrypt {
						log.Printf("[Meta] '%s.%s' gateway:encrypt", table, col)
					}
				}
			}
			cacheMu.Unlock()

			if len(results) == 0 {
				log.Println("[Meta] Nenhuma tabela encontrada no schema public")
			}
			return nil
		}
	}
}

func (s *Session) proxyClientToDB() {
	for {
		msgType, payload, err := readWireMessage(s.clientConn)
		if err != nil {
			return
		}

		newPayload, filterCtx := s.parser.processMessage(msgType, payload)

		if filterCtx.ColName != "" {
			s.filterColName = filterCtx.ColName
			s.filterValue = filterCtx.Value
		}
		if err := writeWireMessage(s.dbConn, msgType, newPayload); err != nil {
			return
		}
	}
}

func (s *Session) proxyDBToClient() {
	for {
		msgType, payload, err := readWireMessage(s.dbConn)
		if err != nil {
			return
		}

		if msgType == 'T' {
			s.parseRowDescription(payload)
			if err := writeWireMessage(s.clientConn, msgType, payload); err != nil {
				return
			}
			continue
		}

		if s.intercepting {
			if msgType == 'D' {
				vals := parseDataRowBytes(payload)
				modified := false

				for _, target := range s.decryptTargets {
					if target.ColIndex < len(vals) {
						val := vals[target.ColIndex]
						if len(val) >= 176 {
							encHex := string(val)
							encBytes, err := hex.DecodeString(encHex)
							if err == nil && len(encBytes) >= 60+12+16 {
								wrappedDek := encBytes[:60]
								dataBytes := encBytes[60:]

								kekBlock, _ := aes.NewCipher(masterDEK)
								kekGcm, _ := cipher.NewGCM(kekBlock)
								kekNonce, kekCipher := wrappedDek[:12], wrappedDek[12:]
								dek, errDek := kekGcm.Open(nil, kekNonce, kekCipher, nil)

								if errDek == nil && len(dek) == 32 {
									dekBlock, _ := aes.NewCipher(dek)
									dekGcm, _ := cipher.NewGCM(dekBlock)
									dekNonce, dataCipher := dataBytes[:12], dataBytes[12:]
									plaintext, errData := dekGcm.Open(nil, dekNonce, dataCipher, nil)

									if errData == nil {
										vals[target.ColIndex] = plaintext
										modified = true
									}
								}
							}
						}
					}
				}

				if s.filterColIndex >= 0 && s.filterColIndex < len(vals) && s.filterValue != "" {
					plaintextVal := string(vals[s.filterColIndex])
					if !strings.Contains(strings.ToLower(plaintextVal), strings.ToLower(s.filterValue)) {
						continue
					}
				}

				s.rowsSent++
				newPayload := payload
				if modified {
					newPayload = buildDataRow(vals)
				}
				if err := writeWireMessage(s.clientConn, 'D', newPayload); err != nil {
					return
				}
				continue
			} else if msgType == 'C' {
				if s.filterColIndex >= 0 {
					cmdStr := string(payload)
					parts := strings.Split(cmdStr, " ")
					if len(parts) > 1 {
						parts[len(parts)-1] = fmt.Sprintf("%d\x00", s.rowsSent)
						newCmd := strings.Join(parts, " ")
						payload = []byte(newCmd)
					}
				}
				s.intercepting = false
			} else if msgType == 'Z' || msgType == 'E' {
				s.intercepting = false
			}
		}

		if err := writeWireMessage(s.clientConn, msgType, payload); err != nil {
			return
		}
	}
}

func (s *Session) parseRowDescription(payload []byte) {
	s.intercepting = false
	s.decryptTargets = nil
	s.filterColIndex = -1

	pos := 0
	if pos+2 > len(payload) {
		return
	}
	numCols := int(binary.BigEndian.Uint16(payload[pos : pos+2]))
	pos += 2

	for i := 0; i < numCols; i++ {
		end := bytes.IndexByte(payload[pos:], 0)
		if end < 0 {
			break
		}
		colName := string(payload[pos : pos+end])
		pos += end + 1

		if pos+18 > len(payload) {
			break
		}
		tableOID := int32(binary.BigEndian.Uint32(payload[pos : pos+4]))
		pos += 18

		if s.filterColName != "" && strings.EqualFold(colName, s.filterColName) {
			s.filterColIndex = i
		}

		if tableName, ok := s.parser.getTableNameFromOID(tableOID); ok {
			tableMeta, hasMeta := s.parser.getTableMeta(tableName)
			if hasMeta {
				if sec, colExists := tableMeta.Columns[colName]; colExists && sec.Encrypt {
					s.intercepting = true
					s.decryptTargets = append(s.decryptTargets, DecryptTarget{
						ColIndex:  i,
						TableName: tableName,
					})
				}
			}
		}
	}
}

/*
func (s *Session) flushDataRows() {
	defer func() {
		s.intercepting = false
	}()

	if len(s.dataRowBuffer) == 0 {
		s.sendTailBuffer()
		return
	}

	// 1. Extrair row_ids
	rowIDs := make(map[string]bool)
	for _, payload := range s.dataRowBuffer {
		vals := parseDataRowBytes(payload)
		for _, target := range s.decryptTargets {
			if target.ColIndex < len(vals) {
				val := vals[target.ColIndex]
				if len(val) >= 32 {
					rowIDs[string(val[:32])] = true
		if s.filterColName != "" && strings.EqualFold(colName, s.filterColName) {
			s.filterColIndex = i
		}
				}
			}
		}
	}

	if len(rowIDs) == 0 {
		s.sendDataRowBuffer()
		s.sendTailBuffer()
		return
	}

	// 2. Buscar DEKs com SimpleQuery
	var ids []string
	for id := range rowIDs {
		ids = append(ids, id)
	}
	query := fmt.Sprintf("SELECT row_id, wrapped_dek FROM gateway_wrapped_deks WHERE row_id IN ('%s')", strings.Join(ids, "','"))

	if err := sendSimpleQuery(s.dbConn, query); err != nil {
		log.Printf("[Decrypt] Erro buscando DEKs: %v", err)
		s.sendDataRowBuffer()
		s.sendTailBuffer()
		return
	}

	dekMap := make(map[string][]byte) // row_id -> unwrapped_dek

	for {
		mt, pl, err := readWireMessage(s.dbConn)
		if err != nil {
			log.Printf("[Decrypt] Erro lendo DEKs: %v", err)
			break
		}
		if mt == 'D' {
			vals := parseDataRowBytes(pl)
			if len(vals) >= 2 && vals[0] != nil && vals[1] != nil {
				rID := string(vals[0])
				wrappedHex := string(vals[1])

				// Handle \x prefix if column is BYTEA
				if strings.HasPrefix(wrappedHex, "\\x") {
					wrappedHex = wrappedHex[2:]
				}

				wrapped, err := hex.DecodeString(wrappedHex)
				if err != nil {
					log.Printf("[Decrypt] Erro de hex decode para %s: %v", rID, err)
					continue
				}

				unwrapped, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, wrapped, nil)
				if err == nil {
					dekMap[rID] = unwrapped
				} else {
					log.Printf("[Decrypt] Erro RSA para %s: %v", rID, err)
				}
			}
		} else if mt == 'E' {
			log.Printf("[Decrypt] DB Error fetching DEKs: %s", string(pl))
		} else if mt == 'Z' {
			break
		}
	}

	// 3. Descriptografar e reescrever DataRows
	for _, payload := range s.dataRowBuffer {
		vals := parseDataRowBytes(payload)
		modified := false
		for _, target := range s.decryptTargets {
			if target.ColIndex < len(vals) {
				val := vals[target.ColIndex]
				if len(val) >= 32 {
					rID := string(val[:32])
					dek, ok := dekMap[rID]
					if ok {
						encHex := string(val[32:])
						encBytes, err := hex.DecodeString(encHex)
						if err == nil {
							block, _ := aes.NewCipher(dek)
							gcm, _ := cipher.NewGCM(block)
							nonceSize := gcm.NonceSize()
							if len(encBytes) > nonceSize {
								nonce, ciphertext := encBytes[:nonceSize], encBytes[nonceSize:]
								plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
								if err == nil {
									vals[target.ColIndex] = plaintext
									modified = true
								}
							}
						}
					}
				}
			}
		}

		newPayload := payload
		if modified {
			newPayload = buildDataRow(vals)
		}
		writeWireMessage(s.clientConn, 'D', newPayload)
	}

	s.sendTailBuffer()
}
*/

// ----------------------------------------------------------------------------------
// Parser
// ----------------------------------------------------------------------------------

func (p *PgParser) processMessage(msgType byte, payload []byte) ([]byte, FilterContext) {
	switch msgType {
	case 'P':
		return p.parseParse(payload), FilterContext{}
	case 'B':
		return p.parseBind(payload)
	default:
		return payload, FilterContext{}
	}
}

func (p *PgParser) parseParse(payload []byte) []byte {
	pos := 0

	stmtEnd := bytes.IndexByte(payload[pos:], 0)
	if stmtEnd < 0 {
		return payload
	}
	stmtName := string(payload[pos : pos+stmtEnd])
	pos += stmtEnd + 1

	queryEnd := bytes.IndexByte(payload[pos:], 0)
	if queryEnd < 0 {
		return payload
	}
	query := string(payload[pos : pos+queryEnd])

	numParamsPos := pos + queryEnd + 1
	if numParamsPos+2 > len(payload) {
		return payload
	}
	numParams := int(binary.BigEndian.Uint16(payload[numParamsPos : numParamsPos+2]))

	tree, err := pg_query.Parse(query)
	if err != nil || len(tree.Stmts) == 0 {
		return payload
	}

	if insertStmt := tree.Stmts[0].Stmt.GetInsertStmt(); insertStmt != nil {
		table := insertStmt.Relation.Relname
		tableMeta, ok := p.getTableMeta(table)
		if !ok {
			return payload
		}

		columns := make([]string, 0)
		blindIndexes := make([]BlindIndexGen, 0)
		addedBlindIndexes := make([]string, 0)

		for i, item := range insertStmt.Cols {
			target := item.GetResTarget()
			if target != nil {
				colName := strings.ToLower(target.Name)
				columns = append(columns, colName)

				if sec, exists := tableMeta.Columns[colName]; exists && sec.BlindIndex != "" {
					addedBlindIndexes = append(addedBlindIndexes, sec.BlindIndex)
					blindIndexes = append(blindIndexes, BlindIndexGen{SourceIndex: i})
				}
			}
		}

		p.statements[stmtName] = StatementMetaData{
			Table:              table,
			Columns:            columns,
			InsertBlindIndexes: blindIndexes,
		}

		if len(addedBlindIndexes) == 0 {
			log.Printf("[Parse] INSERT em '%s', mas sem blind indexes. Passando direto.", table)
			return payload
		}

		selectStmt := insertStmt.SelectStmt.GetSelectStmt()
		if selectStmt == nil || len(selectStmt.ValuesLists) == 0 {
			return payload
		}
		valuesList := selectStmt.ValuesLists[0].GetList()

		for _, targetCol := range addedBlindIndexes {
			insertStmt.Cols = append(insertStmt.Cols, &pg_query.Node{
				Node: &pg_query.Node_ResTarget{
					ResTarget: &pg_query.ResTarget{
						Name: targetCol,
					},
				},
			})

			valuesList.Items = append(valuesList.Items, &pg_query.Node{
				Node: &pg_query.Node_ParamRef{
					ParamRef: &pg_query.ParamRef{
						Number:   int32(len(valuesList.Items) + 1),
						Location: -1,
					},
				},
			})
		}

		newQuery, err := pg_query.Deparse(tree)
		if err != nil {
			log.Printf("[Parse] Erro no deparse: %v", err)
			return payload
		}

		log.Printf("[Parse] Query reescrita para Blind Index: %s", newQuery)

		newPayload := make([]byte, 0, len(payload)+len(newQuery)-len(query)+len(addedBlindIndexes)*4)
		newPayload = append(newPayload, []byte(stmtName)...)
		newPayload = append(newPayload, 0)
		newPayload = append(newPayload, []byte(newQuery)...)
		newPayload = append(newPayload, 0)

		newNumParams := numParams + len(addedBlindIndexes)
		npBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(npBytes, uint16(newNumParams))
		newPayload = append(newPayload, npBytes...)

		oldParamOIDsSize := numParams * 4
		newPayload = append(newPayload, payload[numParamsPos+2:numParamsPos+2+oldParamOIDsSize]...)

		for i := 0; i < len(addedBlindIndexes); i++ {
			newPayload = append(newPayload, 0, 0, 0, 0)
		}

		return newPayload
	}

	if selectStmt := tree.Stmts[0].Stmt.GetSelectStmt(); selectStmt != nil {
		selectParamMap := make(map[int]string)

		var filterColName string
		var filterParamIndex int = -1

		cacheMu.RLock()
		for _, meta := range metadataCache {
			for colName, colMeta := range meta.Columns {
				if colMeta.BlindIndex != "" {
					pattern := `(?i)` + regexp.QuoteMeta(colMeta.BlindIndex) + `"?\s*=\s*\$([0-9]+)`
					re := regexp.MustCompile(pattern)
					matches := re.FindAllStringSubmatch(query, -1)
					for _, match := range matches {
						if paramIndex, err := strconv.Atoi(match[1]); err == nil {
							selectParamMap[paramIndex-1] = colMeta.BlindIndex // 0-based
							log.Printf("[Parse] Detectado blind index busca param $%d = %s", paramIndex, colMeta.BlindIndex)
						}
					}
				}

				if colMeta.Encrypt {
					patternLike := `(?i)` + regexp.QuoteMeta(colName) + `"?\s+(?:I)?LIKE\s+\$([0-9]+)`
					reLike := regexp.MustCompile(patternLike)
					if matches := reLike.FindStringSubmatch(query); len(matches) > 1 {
						if paramIndex, err := strconv.Atoi(matches[1]); err == nil {
							filterColName = colName
							filterParamIndex = paramIndex - 1 // 0-based
							log.Printf("[Parse] Detectado LIKE intercept para coluna '%s' no param $%d", colName, paramIndex)
							replacement := fmt.Sprintf("CAST($%d AS VARCHAR) IS NOT NULL", paramIndex)
							query = reLike.ReplaceAllString(query, replacement)

							newPayload := make([]byte, 0, len(payload))
							pos := 0
							stmtEnd := bytes.IndexByte(payload, 0)
							newPayload = append(newPayload, payload[:stmtEnd+1]...)

							newPayload = append(newPayload, []byte(query)...)
							newPayload = append(newPayload, 0)

							pos = bytes.IndexByte(payload[stmtEnd+1:], 0) + stmtEnd + 2
							newPayload = append(newPayload, payload[pos:]...)

							payload = newPayload
						}
					}
				}
			}
		}
		cacheMu.RUnlock()

		if len(selectParamMap) > 0 || filterColName != "" {
			p.statements[stmtName] = StatementMetaData{
				SelectBlindIndexMap: selectParamMap,
				FilterColName:       filterColName,
				FilterParamIndex:    filterParamIndex,
			}
		}
	}

	return payload
}

func (p *PgParser) parseBind(payload []byte) ([]byte, FilterContext) {
	pos := 0

	portalEnd := bytes.IndexByte(payload[pos:], 0)
	if portalEnd < 0 {
		return payload, FilterContext{}
	}
	portal := payload[pos : pos+portalEnd+1]
	pos += portalEnd + 1

	stmtEnd := bytes.IndexByte(payload[pos:], 0)
	if stmtEnd < 0 {
		return payload, FilterContext{}
	}
	stmtNameBytes := payload[pos : pos+stmtEnd+1]
	stmtName := string(payload[pos : pos+stmtEnd])
	pos += stmtEnd + 1

	if pos+2 > len(payload) {
		return payload, FilterContext{}
	}
	formatCount := int(binary.BigEndian.Uint16(payload[pos : pos+2]))
	pos += 2

	formatCodes := make([]byte, formatCount*2)
	copy(formatCodes, payload[pos:pos+formatCount*2])
	pos += formatCount * 2

	if pos+2 > len(payload) {
		log.Printf("[Bind Debug] Early return at paramCount check. pos=%d, len=%d", pos, len(payload))
		return payload, FilterContext{}
	}
	paramCount := int(binary.BigEndian.Uint16(payload[pos : pos+2]))
	pos += 2

	log.Printf("[Bind Debug] stmtName='%s', formatCount=%d, paramCount=%d", stmtName, formatCount, paramCount)

	params := make([][]byte, 0, paramCount)
	for i := 0; i < paramCount; i++ {
		if pos+4 > len(payload) {
			return payload, FilterContext{}
		}
		size := int(int32(binary.BigEndian.Uint32(payload[pos:])))
		pos += 4
		if size == -1 {
			params = append(params, nil)
			continue
		}
		if pos+size > len(payload) {
			return payload, FilterContext{}
		}
		params = append(params, payload[pos:pos+size])
		pos += size
	}

	rest := payload[pos:]

	stmtMeta, ok := p.statements[stmtName]
	if !ok {
		log.Printf("[Bind Debug] stmtName='%s' NOT FOUND in p.statements! Available keys: %v", stmtName, getMapKeys(p.statements))
		return payload, FilterContext{}
	}

	log.Printf("[Bind Debug] stmtMeta FOUND for '%s'. SelectBlindIndexMap len=%d", stmtName, len(stmtMeta.SelectBlindIndexMap))

	filterCtx := FilterContext{}

	if stmtMeta.FilterColName != "" && stmtMeta.FilterParamIndex >= 0 && stmtMeta.FilterParamIndex < len(params) {
		val := params[stmtMeta.FilterParamIndex]
		if val != nil {
			cleanVal := strings.Trim(string(val), "%")
			filterCtx = FilterContext{
				ColName: stmtMeta.FilterColName,
				Value:   cleanVal,
			}
			log.Printf("[Bind-SELECT] Extrai­do filtro parcial para %s: '%s'", stmtMeta.FilterColName, cleanVal)
		}
	}

	if len(stmtMeta.SelectBlindIndexMap) > 0 {
		for idx := range stmtMeta.SelectBlindIndexMap {
			if idx < len(params) && params[idx] != nil {
				originalPlaintext := string(params[idx])
				hmacVal := computeHMAC(params[idx])
				hexHmac := hex.EncodeToString(hmacVal)
				params[idx] = []byte(hexHmac)
				log.Printf("[Bind-SELECT] Hashing param $%d: plaintext='%s' -> hmac='%s'", idx+1, originalPlaintext, hexHmac)
			}
		}

		var newPayload []byte
		newPayload = append(newPayload, portal...)
		newPayload = append(newPayload, stmtNameBytes...)

		fcBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(fcBytes, uint16(formatCount))
		newPayload = append(newPayload, fcBytes...)
		newPayload = append(newPayload, formatCodes...)

		pcBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(pcBytes, uint16(len(params)))
		newPayload = append(newPayload, pcBytes...)

		for _, value := range params {
			if value == nil {
				s := make([]byte, 4)
				binary.BigEndian.PutUint32(s, 0xffffffff)
				newPayload = append(newPayload, s...)
			} else {
				s := make([]byte, 4)
				binary.BigEndian.PutUint32(s, uint32(len(value)))
				newPayload = append(newPayload, s...)
				newPayload = append(newPayload, value...)
			}
		}
		newPayload = append(newPayload, rest...)
		return newPayload, filterCtx
	} else if filterCtx.ColName != "" {
		return payload, filterCtx
	}

	// 2. INSERT query processing
	columns := stmtMeta.Columns
	if len(columns) == 0 || len(params) != len(columns) {
		return payload, FilterContext{}
	}

	tableMeta, ok := p.getTableMeta(stmtMeta.Table)
	if !ok {
		return payload, FilterContext{}
	}

	hasEncrypted := false
	for _, col := range columns {
		if sec, exists := tableMeta.Columns[col]; exists && sec.Encrypt {
			hasEncrypted = true
			break
		}
	}
	if !hasEncrypted {
		return payload, FilterContext{}
	}

	original := make([][]byte, len(params))
	copy(original, params)

	for i, col := range columns {
		if original[i] == nil {
			continue
		}
		sec, exists := tableMeta.Columns[col]
		if !exists || !sec.Encrypt {
			continue
		}

		encrypted, err := encryptValue(masterDEK, original[i])
		if err != nil {
			log.Printf("[Bind] Erro criptografando '%s': %v", col, err)
			return payload, FilterContext{}
		}
		params[i] = []byte(hex.EncodeToString(encrypted))
	}

	for _, bi := range stmtMeta.InsertBlindIndexes {
		if bi.SourceIndex < len(original) && original[bi.SourceIndex] != nil {
			hmacVal := computeHMAC(original[bi.SourceIndex])
			params = append(params, []byte(hex.EncodeToString(hmacVal)))
		} else {
			params = append(params, nil)
		}
	}
	var newFormatCodes []byte
	var newFormatCount = formatCount

	if formatCount == 0 || formatCount == 1 {
		newFormatCodes = formatCodes
	} else if formatCount == paramCount {
		newFormatCodes = append(newFormatCodes, formatCodes...)
		for i := 0; i < len(stmtMeta.InsertBlindIndexes); i++ {
			newFormatCodes = append(newFormatCodes, 0, 0)
		}
		newFormatCount = paramCount + len(stmtMeta.InsertBlindIndexes)
	}

	// Rebuild payload
	var newPayload []byte
	newPayload = append(newPayload, portal...)
	newPayload = append(newPayload, stmtNameBytes...)

	fcBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(fcBytes, uint16(newFormatCount))
	newPayload = append(newPayload, fcBytes...)
	newPayload = append(newPayload, newFormatCodes...)

	pcBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(pcBytes, uint16(len(params)))
	newPayload = append(newPayload, pcBytes...)

	for _, value := range params {
		if value == nil {
			s := make([]byte, 4)
			binary.BigEndian.PutUint32(s, 0xffffffff)
			newPayload = append(newPayload, s...)
		} else {
			s := make([]byte, 4)
			binary.BigEndian.PutUint32(s, uint32(len(value)))
			newPayload = append(newPayload, s...)
			newPayload = append(newPayload, value...)
		}
	}
	newPayload = append(newPayload, rest...)

	log.Printf("[Bind] Criptografado: table='%s'", stmtMeta.Table)

	return newPayload, FilterContext{}
}

func getMapKeys(m map[string]StatementMetaData) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func computeHMAC(data []byte) []byte {
	mac := hmac.New(sha256.New, []byte("blind_index_secret_key"))  //mudar
	mac.Write(data)
	return mac.Sum(nil)
}

func (p *PgParser) getTableMeta(table string) (TableMetadata, bool) {
	key := p.database + "." + table
	cacheMu.RLock()
	meta, ok := metadataCache[key]
	cacheMu.RUnlock()
	return meta, ok
}

func (p *PgParser) getTableNameFromOID(oid int32) (string, bool) {
	oidMap := map[int32]string{
		16385: "patients", // mudar
	}
	name, ok := oidMap[oid]
	if !ok {
		name = "patients"
		ok = true
	}
	return name, ok
}


func encryptValue(kek, data []byte) ([]byte, error) {
	dek := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, err
	}

	kekBlock, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	kekGcm, err := cipher.NewGCM(kekBlock)
	if err != nil {
		return nil, err
	}
	kekNonce := make([]byte, kekGcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, kekNonce); err != nil {
		return nil, err
	}
	wrappedDek := kekGcm.Seal(kekNonce, kekNonce, dek, nil)

	dekBlock, err := aes.NewCipher(dek)
	if err != nil {
		return nil, err
	}
	dekGcm, err := cipher.NewGCM(dekBlock)
	if err != nil {
		return nil, err
	}
	dekNonce := make([]byte, dekGcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, dekNonce); err != nil {
		return nil, err
	}
	encryptedData := dekGcm.Seal(dekNonce, dekNonce, data, nil)

	result := append(wrappedDek, encryptedData...)
	return result, nil
}

func escapeSQL(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}
