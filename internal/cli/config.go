package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"
)

const DefaultUserAgent = "JerrysRevenge/0.4.0 (authorized Tomcat validation)"

type Config struct {
	URL               string
	List              string
	TryBypass         bool
	Brute             bool
	Wordlist          string
	Company           string
	Threads           int
	ContinueOnSuccess bool
	Ghostcat          bool
	GhostcatFile      string
	GhostcatOutputDir string
	AJPHost           string
	AJPPort           int
	DeployCheck       bool
	WarFile           string
	Username          string
	Password          string
	CredentialsFile   string
	Timeout           time.Duration
	Delay             time.Duration
	Insecure          bool
	Execute           bool
	Report            string
	CredentialOutput  string
	UserAgent         string
	ShowVersion       bool
}

func Parse(args []string, stderr io.Writer, now time.Time) (Config, error) {
	var cfg Config
	fs := flag.NewFlagSet("jerrysrevenge", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&cfg.URL, "u", "", "single base URL (HTTP or HTTPS)")
	fs.StringVar(&cfg.URL, "url", "", "single base URL (HTTP or HTTPS)")
	fs.StringVar(&cfg.List, "l", "", "file containing one base URL per line")
	fs.StringVar(&cfg.List, "list", "", "file containing one base URL per line")
	fs.BoolVar(&cfg.TryBypass, "trybypass", false, "test semicolon-delimited path-parameter variants")
	fs.BoolVar(&cfg.Brute, "b", false, "enable Tomcat Manager credential validation")
	fs.BoolVar(&cfg.Brute, "brute", false, "enable Tomcat Manager credential validation")
	fs.StringVar(&cfg.Wordlist, "w", "", "username:password wordlist; overrides the bundled list")
	fs.StringVar(&cfg.Wordlist, "wordlist", "", "username:password wordlist; overrides the bundled list")
	fs.StringVar(&cfg.Company, "company", "", "add bounded password candidates derived from an organization name")
	fs.IntVar(&cfg.Threads, "t", 4, "global limit for concurrent HTTP requests")
	fs.IntVar(&cfg.Threads, "threads", 4, "global limit for concurrent HTTP requests")
	fs.BoolVar(&cfg.ContinueOnSuccess, "continue-on-success", false, "continue through the wordlist after a valid credential is found")
	fs.BoolVar(&cfg.Ghostcat, "ghostcat", false, "perform one explicitly authorized CVE-2020-1938 AJP file-read attempt")
	fs.StringVar(&cfg.GhostcatFile, "ghostcat-file", "WEB-INF/web.xml", "web-application-relative file for --ghostcat")
	fs.StringVar(&cfg.GhostcatOutputDir, "ghostcat-output-dir", filepath.Join("restricted", "ghostcat"), "mode-0700 directory for mode-0600 Ghostcat response evidence")
	fs.StringVar(&cfg.AJPHost, "ajp-host", "", "explicit AJP host for one --url target; defaults to its hostname")
	fs.IntVar(&cfg.AJPPort, "ajp-port", 8009, "AJP port for --ghostcat")
	fs.BoolVar(&cfg.DeployCheck, "e", false, "run a reversible static-canary deployment check; never executes commands")
	fs.BoolVar(&cfg.DeployCheck, "exploit", false, "run a reversible static-canary deployment check; never executes commands")
	fs.StringVar(&cfg.WarFile, "war-file", "", "canonical static-canary WAR; defaults to an in-memory canary")
	fs.StringVar(&cfg.Username, "U", "", "Tomcat Manager username for --exploit without --brute")
	fs.StringVar(&cfg.Username, "username", "", "Tomcat Manager username for --exploit without --brute")
	fs.StringVar(&cfg.Password, "P", "", "Tomcat Manager password for --exploit without --brute (visible in process arguments)")
	fs.StringVar(&cfg.Password, "password", "", "Tomcat Manager password for --exploit without --brute (visible in process arguments)")
	fs.StringVar(&cfg.CredentialsFile, "creds-file", "", "file containing exactly one username:password pair for --exploit")
	fs.DurationVar(&cfg.Timeout, "timeout", 10*time.Second, "per-request timeout")
	fs.DurationVar(&cfg.Delay, "delay", 0, "global minimum interval between request starts")
	fs.BoolVar(&cfg.Insecure, "k", false, "accept invalid TLS certificates")
	fs.BoolVar(&cfg.Insecure, "insecure", false, "accept invalid TLS certificates")
	fs.BoolVar(&cfg.Execute, "execute", false, "confirm authorization and send requests; without this flag, only print the plan")
	fs.StringVar(&cfg.Report, "report", "", "path for the sanitized runbook (must not already exist)")
	fs.StringVar(&cfg.CredentialOutput, "credential-inventory", filepath.Join("restricted", "jerrysrevenge-credentials.jsonl"), "restricted credential inventory (mode 0600)")
	fs.StringVar(&cfg.UserAgent, "user-agent", DefaultUserAgent, "HTTP User-Agent")
	fs.BoolVar(&cfg.ShowVersion, "version", false, "display the tool version")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: jerrysrevenge (-u URL | -l FILE) [options]")
		fmt.Fprintln(stderr, "\nFor safety, the first run without --execute only prints and records the plan.")
		fmt.Fprintln(stderr, "\nOptions:")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}
	visited := make(map[string]bool)
	fs.Visit(func(item *flag.Flag) {
		visited[item.Name] = true
	})
	if fs.NArg() != 0 {
		return Config{}, fmt.Errorf("%d unexpected positional argument(s)", fs.NArg())
	}
	if cfg.ShowVersion {
		return cfg, nil
	}
	if (cfg.URL == "") == (cfg.List == "") {
		return Config{}, errors.New("provide exactly one of -u/--url or -l/--list")
	}
	if cfg.Threads < 1 || cfg.Threads > 128 {
		return Config{}, errors.New("threads must be between 1 and 128")
	}
	if cfg.Timeout <= 0 || cfg.Timeout > 5*time.Minute {
		return Config{}, errors.New("timeout must be greater than zero and no more than 5m")
	}
	if cfg.Delay < 0 {
		return Config{}, errors.New("delay cannot be negative")
	}
	if !cfg.Brute && cfg.Wordlist != "" {
		return Config{}, errors.New("-w/--wordlist requires -b/--brute")
	}
	if !cfg.Brute && strings.TrimSpace(cfg.Company) != "" {
		return Config{}, errors.New("--company requires -b/--brute")
	}
	if visited["company"] && strings.TrimSpace(cfg.Company) == "" {
		return Config{}, errors.New("--company cannot be empty")
	}
	if cfg.ContinueOnSuccess && !cfg.Brute {
		return Config{}, errors.New("--continue-on-success requires -b/--brute")
	}
	ghostcatOptionSet := visited["ghostcat-file"] || visited["ghostcat-output-dir"] || visited["ajp-host"] || visited["ajp-port"]
	if !cfg.Ghostcat && ghostcatOptionSet {
		return Config{}, errors.New("--ghostcat-file, --ghostcat-output-dir, --ajp-host, and --ajp-port require --ghostcat")
	}
	if cfg.Ghostcat {
		if cfg.AJPPort < 1 || cfg.AJPPort > 65535 {
			return Config{}, errors.New("ajp-port must be between 1 and 65535")
		}
		if strings.TrimSpace(cfg.GhostcatFile) == "" {
			return Config{}, errors.New("ghostcat-file cannot be empty")
		}
		if strings.TrimSpace(cfg.GhostcatOutputDir) == "" {
			return Config{}, errors.New("ghostcat-output-dir cannot be empty")
		}
		if cfg.List != "" && strings.TrimSpace(cfg.AJPHost) != "" {
			return Config{}, errors.New("--ajp-host cannot be combined with --list; put each intended hostname in its URL")
		}
	}

	directCredential := cfg.Username != "" || cfg.Password != ""
	if directCredential && (cfg.Username == "" || cfg.Password == "") {
		return Config{}, errors.New("-U/--username and -P/--password must be provided together")
	}
	if directCredential && cfg.CredentialsFile != "" {
		return Config{}, errors.New("direct credentials and --creds-file are mutually exclusive")
	}
	if !cfg.DeployCheck && (directCredential || cfg.CredentialsFile != "") {
		return Config{}, errors.New("-U/--username, -P/--password, and --creds-file require -e/--exploit")
	}
	if cfg.DeployCheck && cfg.Brute && (directCredential || cfg.CredentialsFile != "") {
		return Config{}, errors.New("with --brute, --exploit uses a confirmed wordlist finding; do not also provide direct credentials")
	}
	if cfg.DeployCheck && !cfg.Brute && !directCredential && cfg.CredentialsFile == "" {
		return Config{}, errors.New("--exploit without --brute requires -U/--username and -P/--password, or --creds-file")
	}
	if cfg.WarFile != "" && !cfg.DeployCheck {
		return Config{}, errors.New("--war-file requires -e/--exploit")
	}
	if strings.TrimSpace(cfg.UserAgent) == "" {
		return Config{}, errors.New("user-agent cannot be empty")
	}
	if cfg.Report == "" {
		cfg.Report = filepath.Join("reports", "jerrysrevenge-"+now.Format("20060102T150405.000000000-0700")+".md")
	}
	if filepath.Clean(cfg.Report) == filepath.Clean(cfg.CredentialOutput) {
		return Config{}, errors.New("the sanitized report and restricted credential inventory must use different files")
	}
	return cfg, nil
}

func Usage(stderr io.Writer) {
	_, _ = io.WriteString(stderr, "Use -h for help.\n")
}
