# Rating Source Tracking for Context-Aware VEX Ratings

## Overview

This feature implements **rating source tracking** for vulnerability ratings in Dependency-Track's Analysis model. It enables context-aware OWASP and CVSS ratings to be imported from VEX documents while preventing unintended overwrites through a precedence-based system.

## Problem Statement

Previously, OWASP Risk Rating scores were stored at the `Vulnerability` level (global), not at the `Component` level. This was inconsistent with how VEX Analysis states work and prevented storing different OWASP scores for the same vulnerability in different contexts.

**Key Issue:** The same CVE could only have one OWASP score shared across all projects/components, even though the OWASP Risk Rating methodology is **context-dependent**.

## Solution

Ratings (CVSS v2/v3/v4 and OWASP RR) are now stored at the `Analysis` level (component-vulnerability scope) with source tracking to manage precedence.

### Rating Source Hierarchy

Ratings are tracked with their source using the `RatingSource` enum, which enforces the following precedence order (highest to lowest):

1. **POLICY** (Precedence: 4) - Rating applied by organizational policies (highest precedence)
2. **VEX** (Precedence: 3) - Rating from VEX documents, authoritative context-specific assessment
3. **MANUAL** (Precedence: 2) - User-provided rating (analyst notes)
4. **NVD** (Precedence: 1) - Default rating from vulnerability databases

**Rationale:** POLICY has highest precedence to enforce organizational security standards. VEX can overwrite MANUAL assessments as it represents authoritative context-aware analysis. MANUAL ratings serve as analyst notes but are subject to policy enforcement.

### Precedence Rules

- Higher precedence sources can overwrite lower precedence sources
- Equal precedence sources can overwrite each other (updates)
- Lower precedence sources **cannot** overwrite higher precedence sources

**Example:**
```
POLICY (8.0) ← VEX (7.2)     ✗ VEX cannot overwrite POLICY
VEX (7.2)    ← MANUAL (9.0)  ✗ MANUAL cannot overwrite VEX
MANUAL (5.0) ← NVD (5.3)     ✗ NVD cannot overwrite MANUAL
VEX (7.2)    ← VEX (8.5)     ✓ Updated VEX can overwrite previous VEX
POLICY (8.0) ← POLICY (9.0)  ✓ Updated POLICY can overwrite previous POLICY
```

## Architecture

### 1. RatingSource Enum

```java
public enum RatingSource {
    POLICY(4),    // Highest precedence - enforce organizational standards
    VEX(3),       // Authoritative context-aware assessments
    MANUAL(2),    // Analyst notes
    NVD(1)        // Default from vulnerability databases
}
```

**Key Methods:**
- `getPrecedence()` - Returns the precedence level
- `canOverwrite(RatingSource other)` - Determines if this source can overwrite another

### 2. Analysis Model Updates

Added new fields to track rating sources:
```java
private RatingSource cvssV2Source;
private RatingSource cvssV3Source;
private RatingSource cvssV4Source;
private RatingSource owaspSource;
```

### 3. MakeAnalysisCommand Enhancements

New builder methods for setting ratings with sources:
```java
command.withCvssV2(vector, score, RatingSource.VEX)
command.withCvssV3(vector, score, RatingSource.VEX)
command.withCvssV4(vector, score, RatingSource.VEX)
command.withOwasp(vector, score, RatingSource.VEX)
```

### 4. VEX Integration

The `CycloneDXVexImporter` now extracts and imports ratings from VEX documents:

```java
// Ratings from VEX are automatically tagged with RatingSource.VEX
if (cdxVuln.getRatings() != null) {
    for (Rating rating : cdxVuln.getRatings()) {
        if (rating.getMethod() == Method.OWASP) {
            command = command.withOwasp(
                rating.getVector(),
                rating.getScore(),
                RatingSource.VEX);
        }
        // ... CVSS v2/v3/v4 handling
    }
}
```

## Database Schema

### New Columns (v5.8.0)

Added to the `ANALYSIS` table:
- `CVSSV2SOURCE VARCHAR(50)`
- `CVSSV3SOURCE VARCHAR(50)`
- `CVSSV4SOURCE VARCHAR(50)`
- `OWASPSOURCE VARCHAR(50)`

### Indexes

Performance indexes created on all rating source columns:
- `ANALYSIS_CVSSV2SOURCE_IDX`
- `ANALYSIS_CVSSV3SOURCE_IDX`
- `ANALYSIS_CVSSV4SOURCE_IDX`
- `ANALYSIS_OWASPSOURCE_IDX`

## Usage Examples

### Example 1: VEX Import with OWASP Scores

**Scenario:** Import a VEX document from VENS with contextual OWASP Risk Rating scores

```xml
<vulnerabilities>
  <vulnerability ref="urn:cdx:vuln/cve-2024-1234">
    <id>CVE-2024-1234</id>
    <ratings>
      <rating>
        <method>OWASP</method>
        <vector>SL:M/M:M/O:M/S:M/ED:M/EE:M/A:M/ID:M/LC:M/LI:M/LAV:M/LAC:M/FD:M/RD:M/NC:M/PV:M</vector>
        <score>7.2</score>
      </rating>
    </ratings>
    <analysis>
      <state>in-triage</state>
      <detail>Application is internet-facing and handles PII data</detail>
    </analysis>
  </vulnerability>
</vulnerabilities>
```

**Result:**
- OWASP score 7.2 stored with `owaspSource = VEX`
- Analysis state set to `IN_TRIAGE`
- Context details recorded

### Example 2: Precedence in Action

**Timeline:**

1. **Initial State:** NVD provides global CVSS score
   ```
   CVSSv3: 5.3 (Source: NVD)
   ```

2. **Policy Applied:** Organizational policy sets minimum
   ```
   CVSSv3: 8.0 (Source: POLICY) ✓ Overwrites NVD
   ```

3. **VEX Import:** Context-specific assessment
   ```
   CVSSv3: 7.2 (Source: VEX) ✓ Overwrites POLICY
   OWASP: 7.2 (Source: VEX) ✓ New rating
   ```

4. **Manual Override:** Security analyst adjusts after investigation
   ```
   OWASP: 9.0 (Source: MANUAL) ✓ Overwrites VEX
   ```

5. **Updated VEX:** New VEX document imported
   ```
   CVSSv3: 8.5 (Source: VEX) ✓ Overwrites previous VEX
   OWASP: 7.5 (Source: VEX) ✗ Cannot overwrite MANUAL
   ```

**Final State:**
- `CVSSv3: 8.5 (Source: VEX)` - Latest VEX assessment
- `OWASP: 9.0 (Source: MANUAL)` - Analyst's assessment preserved

## Benefits

### ✅ Alignment with Standards
- Follows CycloneDX VEX specification for context-aware ratings
- Consistent with existing Analysis architecture

### ✅ Context-Aware Risk Assessment
The same CVE can have different risk scores based on:
- **System Exposure:** Internet-facing vs internal
- **Data Sensitivity:** PII, financial data, public information
- **Business Criticality:** Production vs development
- **Security Controls:** WAF, rate limiting, input validation

### ✅ Tool Integration
Enables import from tools like:
- **[VENS](https://github.com/venslabs/vens)** - Contextual OWASP Risk Rating generator
- **SBOM/VEX Generators** - Any tool producing CycloneDX VEX with ratings
- **Security Scanners** - Context-aware vulnerability assessment tools

### ✅ Prevents Data Loss
- Manual analyst assessments are protected from automated overwrites
- Policy-based ratings are preserved unless explicitly updated
- Clear audit trail showing rating source and changes

## Testing

Comprehensive unit tests cover:

1. **Precedence Validation**
   - Each source can overwrite appropriate lower-precedence sources
   - Higher-precedence sources block lower-precedence overwrites

2. **Real-World Scenarios**
   - Manual analyst overrides VEX
   - VEX overwrites policy
   - Updated VEX replaces previous VEX

3. **Edge Cases**
   - Null/empty source handling
   - Equal precedence updates
   - All source combinations

Run tests:
```bash
mvn test -Dtest=RatingSourceTest
```

## Migration Guide

### For Existing Installations

1. **Database Migration:**
   - Automatic via Liquibase when upgrading to v5.8.0+
   - New columns will be `NULL` for existing analyses
   - First rating update will populate the source

2. **Existing Ratings:**
   - All existing ratings without a source will be treated as updateable
   - First update will set the source (e.g., MANUAL, VEX, POLICY)

3. **API Compatibility:**
   - Fully backward compatible
   - Rating source fields are optional in API responses
   - Old clients will ignore new fields

### For Tool Developers

If you're developing a tool that imports VEX documents:

```java
// Import VEX with ratings
qm.makeAnalysis(
    new MakeAnalysisCommand(component, vulnerability)
        .withState(AnalysisState.IN_TRIAGE)
        .withOwasp(owaspVector, owaspScore, RatingSource.VEX)
        .withCvssV3(cvssVector, cvssScore, RatingSource.VEX)
        .withCommenter("My VEX Tool")
);
```

## References

- **Issue:** [DependencyTrack/dependency-track#5796](https://github.com/DependencyTrack/dependency-track/issues/5796)
- **CycloneDX Spec:** [Vulnerability Ratings](https://cyclonedx.org/docs/1.7/json/#vulnerabilities_items_ratings)
- **OWASP RR:** [Risk Rating Methodology](https://owasp.org/www-community/OWASP_Risk_Rating_Methodology)
- **VENS Tool:** [github.com/venslabs/vens](https://github.com/venslabs/vens)

## Contributing

Contributions are welcome! Please:

1. Follow the existing code style
2. Add tests for new functionality
3. Update documentation
4. Reference related issues

## License

This feature is part of Dependency-Track and is licensed under the Apache License 2.0.

---

**Questions?** Open an issue on [GitHub](https://github.com/DependencyTrack/hyades-apiserver/issues)
