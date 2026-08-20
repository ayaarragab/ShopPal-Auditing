# Findings

## Security


### 1. Validation Error Disclosure

#### Problem:
`validationMiddleware` returned validation details directly in the user response instead of only returning a generic 400 error.

#### Priority
P1

#### Impact:
An attacker could learn validation rules, field names, and other error details from the API response by sending malformed requests.

#### Root cause:
The middleware in `src/middlewares/validation.middleware.ts:validationMiddleware` trusted client-facing error output and sent `errors.array({ onlyFirstError: true })` back to the caller.

#### Minimal Fix:
Return only a generic `400 Bad Request` response with an error message, and send validation details and request context to the logger instead of the response body.
