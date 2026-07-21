# SIEM Integration

AIST automatically exports findings to SIEM-compatible formats alongside every scan.

## CEF (Common Event Format)

Compatible with: ArcSight, QRadar, Splunk, and most enterprise SIEMs.

Each finding becomes one CEF event.

**File:** `reports/{scan-dir}/aist-{date}-{target}.cef`

### Import to ArcSight

1. Copy the `.cef` file to your ArcSight connector host.
2. Configure a SmartConnector for CEF file ingestion.
3. Point the connector at the exported `.cef` path.
4. Map extension fields (`payloadId`, `category`, `riskScore`, `owasp`) to your use cases.

## Splunk

### File export (default)

**File:** `reports/{scan-dir}/aist-{date}-{target}-splunk.json`

Each line is a Splunk HEC JSON event. Upload via Splunk forwarder or manual import.

### Direct HEC push

Set in `.env`:

```env
SPLUNK_HEC_URL=https://splunk:8088/services/collector
SPLUNK_HEC_TOKEN=your-token
```

Or via CLI:

```bash
aist scan --target https://agent.example.com/chat \
  --splunk-url https://splunk.company.com:8088/services/collector \
  --splunk-token your-hec-token
```

If direct push fails, AIST logs a warning and still completes the scan. File export is always attempted when SIEM export is enabled.

### Splunk queries

After import, use these searches:

**All critical findings:**

```spl
index=ai_security sourcetype=aist:finding severity=Critical
```

**Findings by target:**

```spl
index=ai_security sourcetype=aist:finding target=*agent*
```

**Scan trend over time:**

```spl
index=ai_security sourcetype=aist:scan
| timechart avg(overall_score) by target
```

## Format selection

Export both formats (default):

```bash
aist scan --target https://agent.example.com/chat
```

Export CEF only:

```bash
aist scan --target https://agent.example.com/chat --siem cef
```

Export Splunk only:

```bash
aist scan --target https://agent.example.com/chat --siem splunk
```

## Disabling SIEM export

```bash
aist scan --target https://agent.example.com/chat --no-siem
```
