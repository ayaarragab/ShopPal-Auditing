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

### 2. JWT Algorithm Not Explicitly Set

#### Problem:

`JWTHelper.signAccessToken`, `JWTHelper.signRefreshToken`, and `JWTHelper.verifyToken` did not explicitly pin the JWT signing and verification algorithm.

#### Priority

P1

#### Impact:

Tokens could be issued or accepted under an unintended algorithm if the key material or library defaults changed, weakening token integrity and creating room for algorithm confusion issues.

#### Root cause:

The JWT helper in `src/shared/utils/helpers.ts:57-81` called `jwt.sign(...)` and `jwt.verify(...)` without an explicit `algorithm` allow-list or pinned algorithm setting.

#### Minimal Fix:

Explicitly set the JWT algorithm in `src/shared/utils/helpers.ts:57-81` for both signing and verification, and reject any token whose algorithm does not match the expected allow-list.
