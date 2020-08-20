package prober

import (
	"crypto/tls"
	"database/sql"
	"fmt"
	"net"
	"time"

	"github.com/ribbybibby/ssl_exporter/config"

	mssql "github.com/denisenkom/go-mssqldb"
	pconfig "github.com/prometheus/common/config"
)

// ProbeTDS performs a tds/mssql (Microsoft SQL Server) probe
func ProbeTDS(target string, module config.Module, timeout time.Duration) (*tls.ConnectionState, error) {
	tlsConfig, err := pconfig.NewTLSConfig(&module.TLSConfig)
	if err != nil {
		return nil, err
	}

	targetAddress, targetPort, err := net.SplitHostPort(target)
	if err != nil {
		return nil, err
	}

	if tlsConfig.ServerName == "" {
		tlsConfig.ServerName = targetAddress
	}

	var tlsConn *tls.Conn

	connectionString := fmt.Sprintf(
		"Server=%s; Port=%s; Encrypt=true; Dial Timeout=%d; Connection Timeout=%d; App Name=ssl_exporter;",
		tlsConfig.ServerName,
		targetPort,
		timeout/time.Second,
		timeout/time.Second)
	connector, err := mssql.NewConnector(connectionString)
	if err != nil {
		return nil, err
	}
	connector.NewTLSConn = func(conn net.Conn, config *tls.Config) *tls.Conn {
		// NB we must copy the tls config settings required for the tls
		//    connection to work over the mssql tds connection.
		//    see https://github.com/denisenkom/go-mssqldb/blob/0f454e2ecd6ad8fb4691cdbf10e399e05ca03784/tds.go#L928-L933
		tlsConfig.DynamicRecordSizingDisabled = config.DynamicRecordSizingDisabled
		tlsConn = tls.Client(conn, tlsConfig)
		return tlsConn
	}

	db := sql.OpenDB(connector)
	defer db.Close()

	// NB this is expected to fail with "invalid login" class of errors,
	//    so if we have a tlsConn, we ignore any error.
	err = db.Ping()
	if tlsConn == nil && err != nil {
		return nil, err
	}

	state := tlsConn.ConnectionState()

	return &state, nil
}
