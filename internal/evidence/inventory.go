package evidence

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/w41l3r/JerrysRevenge/internal/tomcat"
)

type inventoryRecord struct {
	ID             string                  `json:"id"`
	FullValue      string                  `json:"full_value"`
	SecretType     string                  `json:"secret_type"`
	Username       string                  `json:"username"`
	Password       string                  `json:"password"`
	Origin         inventoryOrigin         `json:"origin"`
	AssociatedUser string                  `json:"associated_account"`
	UsableSystems  []inventoryUsableSystem `json:"systems_where_potentially_usable"`
	Classification tomcat.Classification   `json:"classification"`
	UseStatus      string                  `json:"use_status"`
}

type inventoryOrigin struct {
	Endpoint      string    `json:"endpoint"`
	EvidenceRef   string    `json:"evidence_ref"`
	WordlistLine  int       `json:"wordlist_line"`
	DiscoveredAt  time.Time `json:"discovered_at"`
	DiscoveryNote string    `json:"discovery_context"`
}

type inventoryUsableSystem struct {
	URL        string                `json:"url"`
	Rationale  string                `json:"rationale"`
	Confidence tomcat.Classification `json:"confidence"`
	UseStatus  string                `json:"use_status"`
}

// Inventory stores unmasked credentials and therefore always uses mode 0600.
type Inventory struct {
	mu   sync.Mutex
	path string
}

func NewInventory(path string) *Inventory {
	return &Inventory{path: path}
}

func (i *Inventory) Append(finding tomcat.CredentialFinding) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.path == "" {
		return fmt.Errorf("restricted inventory path is empty")
	}
	if err := ensureParent(i.path, 0o700); err != nil {
		return err
	}
	if info, err := os.Lstat(i.path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("restricted inventory path must not be a symbolic link")
	} else if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("inspect restricted inventory: %w", err)
	}

	f, err := os.OpenFile(i.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open restricted inventory: %w", err)
	}
	defer f.Close()
	if err := f.Chmod(0o600); err != nil {
		return fmt.Errorf("apply mode 0600 to restricted inventory: %w", err)
	}

	useStatus := "NOT TESTED"
	if finding.Classification == tomcat.Confirmed {
		useStatus = "CONFIRMED"
	}
	record := inventoryRecord{
		ID:             finding.ID,
		FullValue:      finding.Username + ":" + finding.Password,
		SecretType:     "HTTP Basic username/password",
		Username:       finding.Username,
		Password:       finding.Password,
		AssociatedUser: finding.Username,
		Classification: finding.Classification,
		UseStatus:      useStatus,
		Origin: inventoryOrigin{
			Endpoint:      finding.Endpoint,
			EvidenceRef:   finding.CredentialRef,
			WordlistLine:  finding.SourceLine,
			DiscoveredAt:  finding.ObservedAt,
			DiscoveryNote: finding.Outcome,
		},
		UsableSystems: []inventoryUsableSystem{{
			URL:        finding.Endpoint,
			Rationale:  finding.Outcome,
			Confidence: finding.Classification,
			UseStatus:  useStatus,
		}},
	}
	encoder := json.NewEncoder(f)
	encoder.SetEscapeHTML(true)
	if err := encoder.Encode(record); err != nil {
		return fmt.Errorf("write restricted inventory: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync restricted inventory: %w", err)
	}
	return nil
}

func (i *Inventory) Path() string {
	return filepath.Clean(i.path)
}
