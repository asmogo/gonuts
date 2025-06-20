package storage

import (
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/elnosh/gonuts/cashu"
	"github.com/elnosh/gonuts/crypto"
	_ "github.com/lib/pq"
)

// PostgreSQL table names
const (
	PG_KEYSETS_TABLE        = "keysets"
	PG_PROOFS_TABLE         = "proofs"
	PG_PENDING_PROOFS_TABLE = "pending_proofs"
	PG_MINT_QUOTES_TABLE    = "mint_quotes"
	PG_MELT_QUOTES_TABLE    = "melt_quotes"
	PG_SEED_TABLE           = "seed"
	PG_MNEMONIC_KEY         = "mnemonic" // Same as MNEMONIC_KEY in bolt.go
)

type PostgresDB struct {
	db *sql.DB
}

func InitPostgres(connStr string) (*PostgresDB, error) {
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, fmt.Errorf("error connecting to postgres: %v", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("error pinging postgres: %v", err)
	}

	pgdb := &PostgresDB{db: db}
	err = pgdb.initWalletTables()
	if err != nil {
		return nil, fmt.Errorf("error setting up postgres tables: %v", err)
	}

	return pgdb, nil
}

func (db *PostgresDB) Close() error {
	return db.db.Close()
}

func (db *PostgresDB) initWalletTables() error {
	// Create tables if they don't exist
	_, err := db.db.Exec(`
		CREATE TABLE IF NOT EXISTS keysets_mint_urls (
			mint_url TEXT PRIMARY KEY
		);

		CREATE TABLE IF NOT EXISTS keysets (
			id TEXT,
			mint_url TEXT REFERENCES keysets_mint_urls(mint_url),
			data JSONB,
			PRIMARY KEY (id, mint_url)
		);

		CREATE TABLE IF NOT EXISTS proofs (
			secret TEXT PRIMARY KEY,
			data JSONB
		);

		CREATE TABLE IF NOT EXISTS pending_proofs (
			y BYTEA PRIMARY KEY,
			data JSONB
		);

		CREATE TABLE IF NOT EXISTS mint_quotes (
			quote_id TEXT PRIMARY KEY,
			data JSONB
		);

		CREATE TABLE IF NOT EXISTS melt_quotes (
			quote_id TEXT PRIMARY KEY,
			data JSONB
		);

		CREATE TABLE IF NOT EXISTS seed (
			key TEXT PRIMARY KEY,
			value BYTEA
		);
	`)

	return err
}

func (db *PostgresDB) SaveMnemonicSeed(mnemonic string, seed []byte) {
	db.db.Exec("INSERT INTO seed (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2", PG_SEED_TABLE, seed)
	db.db.Exec("INSERT INTO seed (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2", PG_MNEMONIC_KEY, []byte(mnemonic))
}

func (db *PostgresDB) GetMnemonic() string {
	var mnemonic []byte
	row := db.db.QueryRow("SELECT value FROM seed WHERE key = $1", PG_MNEMONIC_KEY)
	row.Scan(&mnemonic)
	return string(mnemonic)
}

func (db *PostgresDB) GetSeed() []byte {
	var seed []byte
	row := db.db.QueryRow("SELECT value FROM seed WHERE key = $1", PG_SEED_TABLE)
	row.Scan(&seed)
	return seed
}

func (db *PostgresDB) SaveProofs(proofs cashu.Proofs) error {
	tx, err := db.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare("INSERT INTO proofs (secret, data) VALUES ($1, $2) ON CONFLICT (secret) DO UPDATE SET data = $2")
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, proof := range proofs {
		jsonProof, err := json.Marshal(proof)
		if err != nil {
			return fmt.Errorf("invalid proof: %v", err)
		}
		if _, err := stmt.Exec(proof.Secret, jsonProof); err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (db *PostgresDB) GetProofs() cashu.Proofs {
	proofs := cashu.Proofs{}

	rows, err := db.db.Query("SELECT data FROM proofs")
	if err != nil {
		return proofs
	}
	defer rows.Close()

	for rows.Next() {
		var jsonProof []byte
		if err := rows.Scan(&jsonProof); err != nil {
			continue
		}

		var proof cashu.Proof
		if err := json.Unmarshal(jsonProof, &proof); err != nil {
			continue
		}
		proofs = append(proofs, proof)
	}

	return proofs
}

func (db *PostgresDB) GetProofsByKeysetId(id string) cashu.Proofs {
	proofs := cashu.Proofs{}

	rows, err := db.db.Query("SELECT data FROM proofs WHERE data->>'id' = $1", id)
	if err != nil {
		return proofs
	}
	defer rows.Close()

	for rows.Next() {
		var jsonProof []byte
		if err := rows.Scan(&jsonProof); err != nil {
			continue
		}

		var proof cashu.Proof
		if err := json.Unmarshal(jsonProof, &proof); err != nil {
			continue
		}
		proofs = append(proofs, proof)
	}

	return proofs
}

func (db *PostgresDB) DeleteProof(secret string) error {
	result, err := db.db.Exec("DELETE FROM proofs WHERE secret = $1", secret)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return ProofNotFound
	}

	return nil
}

func (db *PostgresDB) AddPendingProofs(proofs cashu.Proofs) error {
	tx, err := db.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare("INSERT INTO pending_proofs (y, data) VALUES ($1, $2) ON CONFLICT (y) DO UPDATE SET data = $2")
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, proof := range proofs {
		Y, err := crypto.HashToCurve([]byte(proof.Secret))
		if err != nil {
			return err
		}
		Yhex := hex.EncodeToString(Y.SerializeCompressed())

		dbProof := DBProof{
			Y:      Yhex,
			Amount: proof.Amount,
			Id:     proof.Id,
			Secret: proof.Secret,
			C:      proof.C,
			DLEQ:   proof.DLEQ,
		}

		jsonProof, err := json.Marshal(dbProof)
		if err != nil {
			return fmt.Errorf("invalid proof: %v", err)
		}
		if _, err := stmt.Exec(Y.SerializeCompressed(), jsonProof); err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (db *PostgresDB) AddPendingProofsByQuoteId(proofs cashu.Proofs, quoteId string) error {
	tx, err := db.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare("INSERT INTO pending_proofs (y, data) VALUES ($1, $2) ON CONFLICT (y) DO UPDATE SET data = $2")
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, proof := range proofs {
		Y, err := crypto.HashToCurve([]byte(proof.Secret))
		if err != nil {
			return err
		}
		Yhex := hex.EncodeToString(Y.SerializeCompressed())

		dbProof := DBProof{
			Y:           Yhex,
			Amount:      proof.Amount,
			Id:          proof.Id,
			Secret:      proof.Secret,
			C:           proof.C,
			DLEQ:        proof.DLEQ,
			MeltQuoteId: quoteId,
		}

		jsonProof, err := json.Marshal(dbProof)
		if err != nil {
			return fmt.Errorf("invalid proof: %v", err)
		}
		if _, err := stmt.Exec(Y.SerializeCompressed(), jsonProof); err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (db *PostgresDB) GetPendingProofs() []DBProof {
	proofs := []DBProof{}

	rows, err := db.db.Query("SELECT data FROM pending_proofs")
	if err != nil {
		return proofs
	}
	defer rows.Close()

	for rows.Next() {
		var jsonProof []byte
		if err := rows.Scan(&jsonProof); err != nil {
			continue
		}

		var proof DBProof
		if err := json.Unmarshal(jsonProof, &proof); err != nil {
			continue
		}
		proofs = append(proofs, proof)
	}

	return proofs
}

func (db *PostgresDB) GetPendingProofsByQuoteId(quoteId string) []DBProof {
	proofs := []DBProof{}

	rows, err := db.db.Query("SELECT data FROM pending_proofs WHERE data->>'quote_id' = $1", quoteId)
	if err != nil {
		return proofs
	}
	defer rows.Close()

	for rows.Next() {
		var jsonProof []byte
		if err := rows.Scan(&jsonProof); err != nil {
			continue
		}

		var proof DBProof
		if err := json.Unmarshal(jsonProof, &proof); err != nil {
			continue
		}
		proofs = append(proofs, proof)
	}

	return proofs
}

func (db *PostgresDB) DeletePendingProofs(Ys []string) error {
	tx, err := db.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare("DELETE FROM pending_proofs WHERE y = $1")
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, v := range Ys {
		y, err := hex.DecodeString(v)
		if err != nil {
			return fmt.Errorf("invalid Y: %v", err)
		}
		if _, err := stmt.Exec(y); err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (db *PostgresDB) DeletePendingProofsByQuoteId(quoteId string) error {
	// First get all the proofs with this quote ID
	rows, err := db.db.Query("SELECT data FROM pending_proofs WHERE data->>'quote_id' = $1", quoteId)
	if err != nil {
		return err
	}
	defer rows.Close()

	tx, err := db.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare("DELETE FROM pending_proofs WHERE y = $1")
	if err != nil {
		return err
	}
	defer stmt.Close()

	for rows.Next() {
		var jsonProof []byte
		if err := rows.Scan(&jsonProof); err != nil {
			return err
		}

		var proof DBProof
		if err := json.Unmarshal(jsonProof, &proof); err != nil {
			return err
		}

		y, err := hex.DecodeString(proof.Y)
		if err != nil {
			return err
		}
		if _, err := stmt.Exec(y); err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (db *PostgresDB) SaveKeyset(keyset *crypto.WalletKeyset) error {
	jsonKeyset, err := json.Marshal(keyset)
	if err != nil {
		return fmt.Errorf("invalid keyset format: %v", err)
	}

	tx, err := db.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Ensure the mint URL exists in the keysets_mint_urls table
	_, err = tx.Exec("INSERT INTO keysets_mint_urls (mint_url) VALUES ($1) ON CONFLICT (mint_url) DO NOTHING", keyset.MintURL)
	if err != nil {
		return err
	}

	// Insert or update the keyset
	_, err = tx.Exec("INSERT INTO keysets (id, mint_url, data) VALUES ($1, $2, $3) ON CONFLICT (id, mint_url) DO UPDATE SET data = $3",
		keyset.Id, keyset.MintURL, jsonKeyset)
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (db *PostgresDB) GetKeysets() crypto.KeysetsMap {
	keysets := make(crypto.KeysetsMap)

	// Get all mint URLs
	mintRows, err := db.db.Query("SELECT mint_url FROM keysets_mint_urls")
	if err != nil {
		return keysets
	}
	defer mintRows.Close()

	for mintRows.Next() {
		var mintURL string
		if err := mintRows.Scan(&mintURL); err != nil {
			continue
		}

		// Get all keysets for this mint URL
		keysetRows, err := db.db.Query("SELECT data FROM keysets WHERE mint_url = $1", mintURL)
		if err != nil {
			continue
		}
		defer keysetRows.Close()

		mintKeysets := []crypto.WalletKeyset{}
		for keysetRows.Next() {
			var jsonKeyset []byte
			if err := keysetRows.Scan(&jsonKeyset); err != nil {
				continue
			}

			var keyset crypto.WalletKeyset
			if err := json.Unmarshal(jsonKeyset, &keyset); err != nil {
				continue
			}
			mintKeysets = append(mintKeysets, keyset)
		}
		keysetRows.Close()

		keysets[mintURL] = mintKeysets
	}

	return keysets
}

func (db *PostgresDB) GetKeyset(keysetId string) *crypto.WalletKeyset {
	var keyset *crypto.WalletKeyset

	rows, err := db.db.Query("SELECT data FROM keysets WHERE id = $1", keysetId)
	if err != nil {
		return nil
	}
	defer rows.Close()

	if rows.Next() {
		var jsonKeyset []byte
		if err := rows.Scan(&jsonKeyset); err != nil {
			return nil
		}

		keyset = &crypto.WalletKeyset{}
		if err := json.Unmarshal(jsonKeyset, keyset); err != nil {
			return nil
		}
	}

	return keyset
}

func (db *PostgresDB) IncrementKeysetCounter(keysetId string, num uint32) error {
	// Get the keyset
	keyset := db.GetKeyset(keysetId)
	if keyset == nil {
		return errors.New("keyset does not exist")
	}

	// Increment the counter
	keyset.Counter += num

	// Save the updated keyset
	jsonKeyset, err := json.Marshal(keyset)
	if err != nil {
		return fmt.Errorf("invalid keyset format: %v", err)
	}

	_, err = db.db.Exec("UPDATE keysets SET data = $1 WHERE id = $2 AND mint_url = $3",
		jsonKeyset, keyset.Id, keyset.MintURL)
	if err != nil {
		return err
	}

	return nil
}

func (db *PostgresDB) GetKeysetCounter(keysetId string) uint32 {
	keyset := db.GetKeyset(keysetId)
	if keyset == nil {
		return 0
	}
	return keyset.Counter
}

func (db *PostgresDB) UpdateKeysetMintURL(oldURL, newURL string) error {
	tx, err := db.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Check if the old URL exists
	var count int
	err = tx.QueryRow("SELECT COUNT(*) FROM keysets_mint_urls WHERE mint_url = $1", oldURL).Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		return KeysetMintURLNotFound
	}

	// Ensure the new URL exists in the keysets_mint_urls table
	_, err = tx.Exec("INSERT INTO keysets_mint_urls (mint_url) VALUES ($1) ON CONFLICT (mint_url) DO NOTHING", newURL)
	if err != nil {
		return err
	}

	// Get all keysets for the old URL
	rows, err := tx.Query("SELECT id, data FROM keysets WHERE mint_url = $1", oldURL)
	if err != nil {
		return err
	}
	defer rows.Close()

	// Update each keyset's MintURL field and move it to the new URL
	for rows.Next() {
		var id string
		var jsonKeyset []byte
		if err := rows.Scan(&id, &jsonKeyset); err != nil {
			return err
		}

		var keyset crypto.WalletKeyset
		if err := json.Unmarshal(jsonKeyset, &keyset); err != nil {
			return err
		}

		keyset.MintURL = newURL
		updatedKeyset, err := json.Marshal(&keyset)
		if err != nil {
			return err
		}

		// Insert the updated keyset with the new URL
		_, err = tx.Exec("INSERT INTO keysets (id, mint_url, data) VALUES ($1, $2, $3) ON CONFLICT (id, mint_url) DO UPDATE SET data = $3",
			id, newURL, updatedKeyset)
		if err != nil {
			return err
		}

		// Delete the keyset with the old URL
		_, err = tx.Exec("DELETE FROM keysets WHERE id = $1 AND mint_url = $2", id, oldURL)
		if err != nil {
			return err
		}
	}

	// Delete the old URL from keysets_mint_urls
	_, err = tx.Exec("DELETE FROM keysets_mint_urls WHERE mint_url = $1", oldURL)
	if err != nil {
		return err
	}

	return tx.Commit()
}

func (db *PostgresDB) SaveMintQuote(quote MintQuote) error {
	jsonQuote, err := json.Marshal(&quote)
	if err != nil {
		return fmt.Errorf("invalid mint quote: %v", err)
	}

	_, err = db.db.Exec("INSERT INTO mint_quotes (quote_id, data) VALUES ($1, $2) ON CONFLICT (quote_id) DO UPDATE SET data = $2",
		quote.QuoteId, jsonQuote)
	if err != nil {
		return err
	}

	return nil
}

func (db *PostgresDB) GetMintQuotes() []MintQuote {
	var mintQuotes []MintQuote

	rows, err := db.db.Query("SELECT data FROM mint_quotes")
	if err != nil {
		return mintQuotes
	}
	defer rows.Close()

	for rows.Next() {
		var jsonQuote []byte
		if err := rows.Scan(&jsonQuote); err != nil {
			continue
		}

		var quote MintQuote
		if err := json.Unmarshal(jsonQuote, &quote); err != nil {
			continue
		}
		mintQuotes = append(mintQuotes, quote)
	}

	return mintQuotes
}

func (db *PostgresDB) GetMintQuoteById(id string) *MintQuote {
	row := db.db.QueryRow("SELECT data FROM mint_quotes WHERE quote_id = $1", id)

	var jsonQuote []byte
	if err := row.Scan(&jsonQuote); err != nil {
		return nil
	}

	var quote MintQuote
	if err := json.Unmarshal(jsonQuote, &quote); err != nil {
		return nil
	}

	return &quote
}

func (db *PostgresDB) SaveMeltQuote(quote MeltQuote) error {
	jsonQuote, err := json.Marshal(quote)
	if err != nil {
		return fmt.Errorf("invalid melt quote: %v", err)
	}

	_, err = db.db.Exec("INSERT INTO melt_quotes (quote_id, data) VALUES ($1, $2) ON CONFLICT (quote_id) DO UPDATE SET data = $2",
		quote.QuoteId, jsonQuote)
	if err != nil {
		return err
	}

	return nil
}

func (db *PostgresDB) GetMeltQuotes() []MeltQuote {
	var meltQuotes []MeltQuote

	rows, err := db.db.Query("SELECT data FROM melt_quotes")
	if err != nil {
		return meltQuotes
	}
	defer rows.Close()

	for rows.Next() {
		var jsonQuote []byte
		if err := rows.Scan(&jsonQuote); err != nil {
			continue
		}

		var quote MeltQuote
		if err := json.Unmarshal(jsonQuote, &quote); err != nil {
			continue
		}
		meltQuotes = append(meltQuotes, quote)
	}

	return meltQuotes
}

func (db *PostgresDB) GetMeltQuoteById(id string) *MeltQuote {
	row := db.db.QueryRow("SELECT data FROM melt_quotes WHERE quote_id = $1", id)

	var jsonQuote []byte
	err := row.Scan(&jsonQuote)
	if err != nil {
		return nil
	}

	var quote MeltQuote
	if err := json.Unmarshal(jsonQuote, &quote); err != nil {
		return nil
	}

	return &quote
}
