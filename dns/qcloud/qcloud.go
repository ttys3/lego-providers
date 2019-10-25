// Package qcloud implements a DNS provider for solving the DNS-01 challenge using qcloud cns.
package qcloud

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-acme/lego/v3/challenge/dns01"
	"github.com/go-acme/lego/v3/platform/config/env"
	cns "github.com/go-http/qcloud-cns"
)

// Config is used to configure the creation of the DNSProvider
type Config struct {
	SecretId           string
	SecretKey          string
	TTL                int
	PropagationTimeout time.Duration
	PollingInterval    time.Duration
	HTTPClient         *http.Client
}

// NewDefaultConfig returns a default configuration for the DNSProvider
func NewDefaultConfig() *Config {
	return &Config{
		TTL:                env.GetOrDefaultInt("QCLOUD_TTL", 600),
		PropagationTimeout: env.GetOrDefaultSecond("QCLOUD_PROPAGATION_TIMEOUT", dns01.DefaultPropagationTimeout),
		PollingInterval:    env.GetOrDefaultSecond("QCLOUD_POLLING_INTERVAL", dns01.DefaultPollingInterval),
		HTTPClient: &http.Client{
			Timeout: env.GetOrDefaultSecond("QCLOUD_HTTP_TIMEOUT", 0),
		},
	}
}

// DNSProvider is an implementation of the challenge.Provider interface.
type DNSProvider struct {
	config *Config
	client *cns.Client
}

// NewDNSProvider returns a DNSProvider instance configured for qcloud.
// Credentials must be passed in the environment variables: QCLOUD_SECRET_ID and QCLOUD_SECRET_KEY
func NewDNSProvider() (*DNSProvider, error) {
	values, err := env.Get("QCLOUD_SECRET_ID", "QCLOUD_SECRET_KEY")
	if err != nil {
		return nil, fmt.Errorf("qcloud cns: %w", err)
	}

	config := NewDefaultConfig()
	config.SecretId = values["QCLOUD_SECRET_ID"]
	config.SecretKey = values["QCLOUD_SECRET_KEY"]

	return NewDNSProviderConfig(config)
}

// NewDNSProviderConfig return a DNSProvider instance configured for qcloud.
func NewDNSProviderConfig(config *Config) (*DNSProvider, error) {
	if config == nil {
		return nil, errors.New("qcloud cns: the configuration of the DNS provider is nil")
	}

	if config.SecretKey == "" {
		return nil, fmt.Errorf("qcloud cns: credentials missing")
	}

	client := cns.New(config.SecretId, config.SecretKey)
	//client.HttpClient = config.HTTPClient

	return &DNSProvider{client: client, config: config}, nil
}

// Present creates a TXT record to fulfill the dns-01 challenge.
func (d *DNSProvider) Present(domain, token, keyAuth string) error {
	/*
	fixup for wildcard domain
	if it is a wildcard domain, the fqdn will be:
	_acme-challenge.*.example.com.
	then the subdomain name to create will be: _acme-challenge.*
	qcloud does not allow this name to be created, and will return error:
	[4000](RecordCreate.SubDomainInvalid): (810422)子域名不正确 子域名不正确
	 */
	if domain[:2] == "*." {
		domain = domain[2:]
	}
	fqdn, value := dns01.GetRecord(domain, keyAuth)
	_, zoneName, err := d.getHostedZone(domain)
	if err != nil {
		return err
	}

	recordAttributes := d.newTxtRecord(zoneName, fqdn, value, d.config.TTL)
	_, err = d.client.RecordCreate(zoneName, *recordAttributes)
	if err != nil {
		return fmt.Errorf("qcloud cns: RecordCreate() API call failed: %v", err)
	}

	return nil
}

// CleanUp removes the TXT record matching the specified parameters.
func (d *DNSProvider) CleanUp(domain, token, keyAuth string) error {
	// fixup for wildcard domain
	if domain[:2] == "*." {
		domain = domain[2:]
	}
	fqdn, _ := dns01.GetRecord(domain, keyAuth)

	records, err := d.findTxtRecords(domain, fqdn)
	if err != nil {
		return fmt.Errorf("CleanUp(): findTxtRecords err: %w", err)
	}

	_, zoneName, err := d.getHostedZone(domain)
	if err != nil {
		return  fmt.Errorf("CleanUp(): getHostedZone err: %w", err)
	}
	//fmt.Printf("CleanUp(): zoneName: %s\n", zoneName)

	for _, rec := range records {
		err := d.client.RecordDelete(zoneName, rec.Id)
		if err != nil {
			return fmt.Errorf("CleanUp(): qcloud cns: RecordDelete err: %w", err)
		}
	}
	return nil
}

// Timeout returns the timeout and interval to use when checking for DNS propagation.
// Adjusting here to cope with spikes in propagation times.
func (d *DNSProvider) Timeout() (timeout, interval time.Duration) {
	return d.config.PropagationTimeout, d.config.PollingInterval
}

func (d *DNSProvider) getHostedZone(domain string) (string, string, error) {
	zones, err := d.client.DomainList()
	if err != nil {
		return "", "", fmt.Errorf("qcloud cns: DomainList() API call failed: %v", err)
	}

	authZone, err := dns01.FindZoneByFqdn(dns01.ToFqdn(domain))
	if err != nil {
		return "", "", err
	}

	var hostedZone cns.Domain
	for _, zone := range zones {
		if zone.Name == dns01.UnFqdn(authZone) {
			hostedZone = zone
		}
	}

	if hostedZone.Id == 0 {
		return "", "", fmt.Errorf("getHostedZone: zone %s not found in qcloud cns for domain %s", authZone, domain)
	}

	return fmt.Sprintf("%v", hostedZone.Id), hostedZone.Name, nil
}

func (d *DNSProvider) newTxtRecord(zone, fqdn, value string, ttl int) *cns.Record {
	//fmt.Printf("\nzone: %v, fqdn: %v, value: %v\n", zone, fqdn, value)
	//zone: mydomain.com, fqdn: _acme-challenge.mydomain.com., value: ADw2sEd82DUgXcQ9hNBZThJs7zVJkR5v9JeSbAb9mZY---

	name := d.extractRecordName(fqdn, zone)
	//fmt.Printf("\nsubdomain name: %v\n", name)

	return &cns.Record{
		Type:  "TXT",
		Name:  name,
		Value: value,
		Line:  "默认",
		Ttl:   ttl,
	}
}

func (d *DNSProvider) findTxtRecords(domain, fqdn string) ([]cns.Record, error) {
	_, zoneName, err := d.getHostedZone(domain)
	if err != nil {
		return nil, err
	}

	var records []cns.Record
	result, err := d.client.RecordList(zoneName)
	if err != nil {
		return records, fmt.Errorf("qcloud cns: RecordList() API call has failed: %v", err)
	}

	recordName := d.extractRecordName(fqdn, zoneName)

	for _, record := range result {
		if record.Name == recordName {
			records = append(records, record)
		}
	}

	return records, nil
}

func (d *DNSProvider) extractRecordName(fqdn, domain string) string {
	name := dns01.UnFqdn(fqdn)
	if idx := strings.Index(name, "."+domain); idx != -1 {
		return name[:idx]
	}
	return name
}
