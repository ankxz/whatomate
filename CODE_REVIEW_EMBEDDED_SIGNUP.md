# Code Review: Embedded Signup Feature

## Executive Summary

**Overall Assessment**: ⚠️ **MAJOR ISSUES FOUND** - Requires immediate fixes before production

**Status**: Code is functional but has **critical security vulnerabilities** and performance issues that must be addressed.

---

## 🔴 CRITICAL ISSUES (Must Fix Immediately)

### 1. **Unencrypted Sensitive Data Storage** 
**Severity**: CRITICAL  
**File**: `internal/handlers/embedded_signup.go`  
**Lines**: 179, 260, 433

**Issue**:
```go
MetaAppSecret: req.MetaAppSecret, // TODO: encrypt before storing
MetaAccessToken: metaAccessToken, // TODO: encrypt
```

**Impact**: 
- Meta App Secret stored in **plain text** in database
- OAuth access tokens stored **unencrypted**
- If database is compromised, attackers get:
  - Full access to Meta Business accounts
  - Ability to send messages as any customer
  - Access to customer WhatsApp data

**Remediation**:
```go
// Use encryption before storing
import "crypto/aes"
import "crypto/cipher"

// Encrypt sensitive data
encryptedSecret, err := encryptData(req.MetaAppSecret, a.Config.EncryptionKey)
if err != nil {
    return r.SendErrorEnvelope(fasthttp.StatusInternalServerError, "Encryption failed", nil, "")
}
signup.MetaAppSecret = encryptedSecret
```

**Priority**: **IMMEDIATE** - Do not deploy to production without fixing

---

### 2. **SQL Injection via Type Assertion**
**Severity**: CRITICAL  
**File**: `internal/handlers/embedded_signup.go`  
**Lines**: 212, 233, 306, 327, 354, 512

**Issue**:
```go
idStr := r.RequestCtx.UserValue("id").(string)  // Unsafe type assertion
id, err := uuid.Parse(idStr)
```

**Impact**:
- Type assertion can panic if "id" is not a string
- Application crashes, causes denial of service
- No graceful error handling

**Remediation**:
```go
// Safe type assertion
idVal := r.RequestCtx.UserValue("id")
idStr, ok := idVal.(string)
if !ok {
    return r.SendErrorEnvelope(fasthttp.StatusBadRequest, "Invalid ID format", nil, "")
}

id, err := uuid.Parse(idStr)
if err != nil {
    return r.SendErrorEnvelope(fasthttp.StatusBadRequest, "Invalid UUID", nil, "")
}
```

**Priority**: **IMMEDIATE**

---

### 3. **Missing Rate Limiting Implementation**
**Severity**: HIGH  
**File**: `internal/handlers/embedded_signup.go`  
**Line**: 387

**Issue**:
```go
// Rate limiting check (simple in-memory check - can be enhanced with Redis)
// TODO: Implement proper rate limiting with Redis
```

**Impact**:
- Public endpoint has **NO rate limiting**
- Vulnerable to:
  - DDoS attacks
  - Spam signups
  - Abuse of Meta API quota
  - Database flooding

**Remediation**:
```go
// Implement Redis-based rate limiting
key := fmt.Sprintf("signup_rate:%s:%s", signup.ID, ipAddress)
count, err := a.Redis.Incr(r.RequestCtx, key).Result()
if err == nil {
    if count == 1 {
        a.Redis.Expire(r.RequestCtx, key, time.Hour)
    }
    if count > signup.RateLimitPerHour {
        return r.SendErrorEnvelope(fasthttp.StatusTooManyRequests, 
            "Rate limit exceeded", nil, "")
    }
}
```

**Priority**: **HIGH** - Essential for public endpoints

---

### 4. **CORS Bypass - Insecure Default**
**Severity**: HIGH  
**File**: `internal/handlers/embedded_signup.go`  
**Lines**: 600-604

**Issue**:
```go
func isOriginAllowed(origin string, allowedOrigins models.StringArray) bool {
    // If no origins specified, allow all (not recommended for production)
    if len(allowedOrigins) == 0 {
        return true  // ❌ DANGEROUS!
    }
```

**Impact**:
- If admin forgets to set allowed origins → **ANY website can use the signup**
- Phishing websites can embed your signup forms
- Unauthorized lead collection
- Brand reputation damage

**Remediation**:
```go
func isOriginAllowed(origin string, allowedOrigins models.StringArray) bool {
    // Secure default: Deny all if no origins specified
    if len(allowedOrigins) == 0 {
        return false  // ✅ SECURE
    }
    
    // Remove wildcard "*" support or make it explicit
    origin = strings.TrimSpace(strings.ToLower(origin))
    for _, allowed := range allowedOrigins {
        allowed = strings.TrimSpace(strings.ToLower(allowed))
        if origin == allowed {
            return true
        }
        // Wildcard support only for subdomains
        if strings.HasPrefix(allowed, "*.") {
            domain := strings.TrimPrefix(allowed, "*.")
            if strings.HasSuffix(origin, "."+domain) {
                return true
            }
        }
    }
    return false
}
```

**Priority**: **HIGH**

---

### 5. **Phone Number Not Validated**
**Severity**: HIGH  
**File**: `internal/handlers/embedded_signup.go`  
**Lines**: 377-379

**Issue**:
```go
if req.PhoneNumber == "" {
    return r.SendErrorEnvelope(fasthttp.StatusBadRequest, "Phone number is required", nil, "")
}
// No validation of phone number format!
```

**Impact**:
- Invalid phone numbers stored in database
- Failed message delivery
- Wasted Meta API quota
- Poor data quality

**Remediation**:
```go
import "regexp"

// Validate E.164 format: +[country code][number]
phoneRegex := regexp.MustCompile(`^\+[1-9]\d{1,14}$`)
if !phoneRegex.MatchString(req.PhoneNumber) {
    return r.SendErrorEnvelope(fasthttp.StatusBadRequest, 
        "Invalid phone number format. Use E.164: +1234567890", nil, "")
}

// Additional: Check for duplicate signups
var existingLead models.EmbeddedSignupLead
err := a.DB.Where("signup_id = ? AND phone_number = ? AND created_at > ?", 
    signup.ID, req.PhoneNumber, time.Now().Add(-24*time.Hour)).First(&existingLead).Error
if err == nil {
    return r.SendErrorEnvelope(fasthttp.StatusConflict, 
        "Phone number already signed up", nil, "")
}
```

**Priority**: **HIGH**

---

## 🟠 HIGH PRIORITY ISSUES

### 6. **Potential Nil Pointer Dereference**
**Severity**: MEDIUM  
**File**: `internal/handlers/embedded_signup.go`  
**Lines**: 401-410, 482

**Issue**:
```go
metaAccessToken = tokenData["access_token"].(string)  // Panic if key missing or wrong type
if businessID, ok := tokenData["business_id"].(string); ok {
    metaBusinessID = businessID
}

if signup.WelcomeMessage != "" && signup.WhatsAppAccount != nil {  // Good nil check
    // But later:
    WhatsAppAccount: signup.WhatsAppAccount.Name,  // Line 457 - NO nil check!
}
```

**Remediation**:
```go
// Safe type assertion with defaults
if accessToken, ok := tokenData["access_token"].(string); ok {
    metaAccessToken = accessToken
} else {
    a.Log.Error("Missing access_token in OAuth response")
}

// Line 457 - Add nil check
whatsappAccountName := ""
if signup.WhatsAppAccount != nil {
    whatsappAccountName = signup.WhatsAppAccount.Name
}
contact := models.Contact{
    WhatsAppAccount: whatsappAccountName,
    // ...
}
```

---

### 7. **Missing Input Sanitization - XSS Risk**
**Severity**: MEDIUM  
**File**: `internal/handlers/embedded_signup.go`  
**Lines**: 430, 455

**Issue**:
```go
ProfileName: req.ProfileName,  // User input, not sanitized
FormData: models.JSONB(req.FormData),  // Arbitrary JSON, not sanitized
```

**Impact**:
- Stored XSS attacks if data displayed in frontend
- Script injection in profile names
- Malicious data in form fields

**Remediation**:
```go
import "html"

// Sanitize text inputs
sanitizedName := html.EscapeString(strings.TrimSpace(req.ProfileName))
if len(sanitizedName) > 255 {
    sanitizedName = sanitizedName[:255]
}

// Validate FormData structure
for key, value := range req.FormData {
    if str, ok := value.(string); ok {
        req.FormData[key] = html.EscapeString(str)
    }
}
```

---

### 8. **Race Condition in Contact Creation**
**Severity**: MEDIUM  
**File**: `internal/handlers/embedded_signup.go`  
**Lines**: 464-478

**Issue**:
```go
// Check if contact exists
var existingContact models.Contact
if err := a.DB.Where("organization_id = ? AND phone_number = ?", 
    signup.OrganizationID, req.PhoneNumber).First(&existingContact).Error; err == nil {
    // Contact exists, update it
    contact.ID = existingContact.ID
    a.DB.Model(&contact).Updates(...)  // ❌ Race condition!
} else {
    // Create new contact
    if err := a.DB.Create(&contact).Error; err == nil {  // ❌ Can fail if concurrent request
```

**Impact**:
- Concurrent signups with same phone number can create duplicate contacts
- Data inconsistency

**Remediation**:
```go
// Use upsert (ON CONFLICT) with database transaction
tx := a.DB.Begin()
defer func() {
    if r := recover(); r != nil {
        tx.Rollback()
    }
}()

var contact models.Contact
result := tx.Where("organization_id = ? AND phone_number = ?", 
    signup.OrganizationID, req.PhoneNumber).
    Assign(map[string]interface{}{
        "profile_name": req.ProfileName,
        "metadata": models.JSONB(req.FormData),
    }).
    FirstOrCreate(&contact)

if result.Error != nil {
    tx.Rollback()
    return result.Error
}

lead.ContactID = &contact.ID
tx.Save(&lead)
tx.Commit()
```

---

### 9. **Update Handler Allows Overwriting Booleans with Zero Values**
**Severity**: MEDIUM  
**File**: `internal/handlers/embedded_signup.go`  
**Lines**: 284-289

**Issue**:
```go
signup.EnableCoexistence = req.EnableCoexistence  // Can't distinguish false vs not-provided
signup.SyncChatHistory = req.SyncChatHistory
signup.IsActive = req.IsActive
signup.AutoCreateContact = req.AutoCreateContact
```

**Impact**:
- Can't do partial updates
- Sending `{}` will set all booleans to `false`
- User may unintentionally disable features

**Remediation**:
```go
// Use pointers for optional boolean fields
type EmbeddedSignupRequest struct {
    EnableCoexistence *bool `json:"enable_coexistence,omitempty"`
    SyncChatHistory   *bool `json:"sync_chat_history,omitempty"`
    IsActive          *bool `json:"is_active,omitempty"`
    AutoCreateContact *bool `json:"auto_create_contact,omitempty"`
}

// Only update if provided
if req.EnableCoexistence != nil {
    signup.EnableCoexistence = *req.EnableCoexistence
}
```

---

### 10. **Goroutine Leak in Webhook**
**Severity**: MEDIUM  
**File**: `internal/handlers/embedded_signup.go`  
**Line**: 489

**Issue**:
```go
// Trigger webhook if configured
if signup.WebhookURL != nil && *signup.WebhookURL != "" {
    go a.sendEmbeddedSignupWebhook(*signup.WebhookURL, lead, signup.MetaAppSecret)
    // ❌ No error tracking, no monitoring, no retry mechanism
}
```

**Impact**:
- Failed webhooks silently ignored
- No way to know if notification failed
- Memory leak if goroutines accumulate

**Remediation**:
```go
// Use worker queue instead of goroutine
if signup.WebhookURL != nil && *signup.WebhookURL != "" {
    webhookJob := models.Job{
        Type: "embedded_signup_webhook",
        Payload: map[string]interface{}{
            "webhook_url": *signup.WebhookURL,
            "lead_id": lead.ID,
            "signup_id": signup.ID,
        },
        MaxRetries: 3,
    }
    if err := a.Queue.Enqueue(webhookJob); err != nil {
        a.Log.Error("Failed to enqueue webhook", "error", err)
    }
}
```

---

## 🟡 MEDIUM PRIORITY ISSUES

### 11. **Missing Logging for Security Events**

**Issue**: No audit trail for:
- Failed signup attempts
- Rate limit violations
- CORS violations
- Invalid phone numbers

**Remediation**:
```go
a.Log.Warn("Signup attempt blocked", 
    "reason", "invalid_origin",
    "origin", origin,
    "signup_id", signup.ID,
    "ip", ipAddress,
)
```

---

### 12. **No Pagination for Leads Listing**
**Severity**: MEDIUM  
**Line**: 524

**Issue**:
```go
if err := a.DB.Where("signup_id = ?", id).Order("created_at DESC").Find(&leads).Error; err != nil {
    // ❌ Loads ALL leads into memory!
}
```

**Impact**:
- Memory exhaustion with large number of leads
- Slow API responses
- Poor user experience

**Remediation**:
```go
// Add pagination parameters
page := r.RequestCtx.QueryArgs().GetUintOrZero("page")
if page == 0 {
    page = 1
}
limit := 50
offset := (page - 1) * limit

var leads []models.EmbeddedSignupLead
var total int64

a.DB.Model(&models.EmbeddedSignupLead{}).Where("signup_id = ?", id).Count(&total)
a.DB.Where("signup_id = ?", id).
    Order("created_at DESC").
    Limit(limit).
    Offset(offset).
    Find(&leads)

return r.SendEnvelope(map[string]interface{}{
    "leads": response,
    "pagination": map[string]interface{}{
        "page": page,
        "limit": limit,
        "total": total,
        "pages": (total + int64(limit) - 1) / int64(limit),
    },
})
```

---

### 13. **Hardcoded Timeout Values**
**Severity**: LOW  
**Lines**: 643, 693

**Issue**:
```go
client := &http.Client{Timeout: 30 * time.Second}  // Hardcoded
client := &http.Client{Timeout: 10 * time.Second}  // Hardcoded
```

**Remediation**:
```go
// Move to configuration
[http]
oauth_timeout_seconds = 30
webhook_timeout_seconds = 10
```

---

### 14. **Incomplete Error Messages**

**Issue**: Generic error messages don't help debugging:
```go
return r.SendErrorEnvelope(fasthttp.StatusInternalServerError, "Failed to create signup", nil, "")
```

**Remediation**:
```go
// Add error codes and details
return r.SendErrorEnvelope(
    fasthttp.StatusInternalServerError, 
    "Failed to create signup", 
    map[string]interface{}{
        "error_code": "SIGNUP_CREATE_FAILED",
        "details": "Database error",
    }, 
    "",
)
```

---

## ✅ GOOD PRACTICES OBSERVED

1. ✅ **Multi-tenant isolation** - All queries filter by organization_id
2. ✅ **HMAC webhook signatures** - Line 680-682
3. ✅ **CORS validation** - Line 366-369
4. ✅ **Type safety** - Using proper types (uuid.UUID, models.JSONB)
5. ✅ **Structured logging** - Using structured logger
6. ✅ **Response DTOs** - Not exposing internal models directly
7. ✅ **Meta App Secret** excluded from JSON - Line 409 `json:"-"`
8. ✅ **Wildcard subdomain support** - Lines 613-617
9. ✅ **Defensive nil checks** - Lines 543-556

---

## 📊 PERFORMANCE CONCERNS

### 1. **N+1 Query in Preload**
**Line**: 361
```go
.Preload("WhatsAppAccount").First(&signup)
```
Consider using `Select` to load only needed fields.

### 2. **Missing Database Indexes**
Add indexes for:
```sql
CREATE INDEX idx_embedded_signup_leads_phone_created 
  ON embedded_signup_leads(phone_number, created_at DESC);

CREATE INDEX idx_embedded_signup_leads_signup_status 
  ON embedded_signup_leads(signup_id, status);
```

---

## 🔧 CODE QUALITY ISSUES

### 1. **Commented TODO Items**
Multiple TODOs in production code:
- Line 179: `// TODO: encrypt before storing`
- Line 260: `// TODO: encrypt`
- Line 387: `// TODO: Implement proper rate limiting`
- Line 415: `// TODO: Implement chat history sync`
- Line 433: `// TODO: encrypt`
- Line 483: `// TODO: Queue welcome message`

**Action**: Create GitHub issues and implement or remove TODOs.

### 2. **Magic Numbers**
```go
req.RateLimitPerHour = 100  // Line 149 - Why 100?
```

**Recommendation**: Use constants:
```go
const (
    DefaultRateLimitPerHour = 100
    DefaultAPIVersion = "v24.0"
    MaxPhoneNumberLength = 20
    MaxProfileNameLength = 255
)
```

---

## 🧪 TESTING GAPS

**Missing tests for**:
1. Rate limiting behavior
2. CORS validation edge cases
3. Phone number validation
4. Concurrent contact creation
5. Webhook signature validation
6. OAuth code exchange failures
7. Type assertion panics

**Test Coverage Target**: 80%+

---

## 📋 SUMMARY & RECOMMENDATIONS

### Immediate Actions (Before Production):
1. ✅ Implement encryption for secrets and tokens
2. ✅ Add safe type assertions with error handling
3. ✅ Implement Redis-based rate limiting
4. ✅ Change CORS default to deny-all
5. ✅ Add phone number validation
6. ✅ Fix nil pointer dereferences

### Short-term (Next Sprint):
1. Add input sanitization (XSS prevention)
2. Fix race conditions with transactions
3. Implement pagination for leads
4. Add comprehensive logging
5. Move webhooks to queue system
6. Add unit tests (target 80% coverage)

### Long-term:
1. Implement chat history sync (TODO line 415)
2. Implement welcome message queue (TODO line 483)
3. Add monitoring and alerting
4. Performance optimization (caching, indexes)
5. Add integration tests
6. Security audit by third party

---

## 🎯 RISK SCORE

**Overall Risk**: 🔴 **HIGH** (7/10)

**Breakdown**:
- Security: 🔴 HIGH (Unencrypted secrets, no rate limiting)
- Reliability: 🟠 MEDIUM (Panic risks, race conditions)
- Performance: 🟡 LOW-MEDIUM (No pagination, missing indexes)
- Maintainability: 🟢 GOOD (Clean structure, good practices)

---

## ✍️ CONCLUSION

The embedded signup feature is **architecturally sound** and follows many best practices, but has **critical security vulnerabilities** that must be addressed before production deployment.

**Estimated effort to fix critical issues**: 2-3 days  
**Estimated effort for all recommendations**: 1-2 weeks

The code shows good understanding of multi-tenancy, CORS, and webhook security, but needs immediate attention on:
1. Data encryption
2. Rate limiting
3. Input validation
4. Error handling

**Recommendation**: **DO NOT DEPLOY** to production until critical issues are resolved.

---

**Reviewed by**: Claude  
**Date**: 2026-04-18  
**Reviewed Files**:
- `internal/handlers/embedded_signup.go`
- `internal/models/models.go`
- `frontend/src/views/settings/EmbeddedSignupView.vue`
- `docker-compose.dev.yml`
