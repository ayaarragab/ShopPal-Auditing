# Findings

### 1. Login Response Leaks Password Hash

#### Problem:

`UserController.login` returned the full user object — including the bcrypt password hash — in the response body.

#### Priority

P1

#### Status:

Solved

#### Impact:

Every successful login currently returns the user's password hash to the client. An attacker with access to the response (e.g. via logging, browser devtools, a compromised dependency, or network capture on a misconfigured connection) could attempt offline cracking of the hash, and the value should never leave the server in the first place.

#### Root cause:

`UserService.getUser` (`src/api/users/user.service.ts`) returns the full entity produced by `UserRepository.getUserByCredentials`, which selects every column including `password` (see existing Finding "User Lookup Selects Full Entity"). `UserController.login` (`src/api/users/user.controller.ts`) then responds with `res.json({ accessToken, user })` without stripping the password field, unlike `createUser`, which already sanitizes its output.

#### Minimal Fix:

Strip `password` from the `user` object before sending the login response, the same way `UserService.createUser` already does. Fixing the underlying over-selection in `getUserByCredentials` (see existing Finding "User Lookup Selects Full Entity") will also close this.

### 2. Update Product Stock Route Lacks Authorization

#### Problem:

`PATCH /order/` (`OrderController.updateProductsStocks`) was exposed without any authorization middleware.

#### Priority

P1

#### Status:

Solved

#### Impact:

Any unauthenticated caller can overwrite the stock count of any product, since the route has no `authorizationMiddleware` and no ownership or role check of any kind.

#### Root cause:

The router in `src/api/orders/order.router.ts` registers `router.patch('/', checkSchema(updateProductsStocksSchema), validationMiddleware, tryCatchMiddleware(OrderController.updateProductsStocks))` without an authorization middleware before the handler, unlike the other order routes (`GET /:user_id`, `POST /:user_id`, `PATCH /:order_id`, `DELETE /:order_id`), which all require it.

#### Minimal Fix:

Add `authorizationMiddleware` to the `PATCH /` route in `src/api/orders/order.router.ts`, and restrict it to the roles or internal callers (e.g. checkout flow) that are allowed to adjust stock.

### 3. Raw Database Error Messages Returned to Client

#### Problem:

`errorMiddleware` returned the raw `QueryFailedError.message` from TypeORM/pg directly in the API response.

#### Priority

P2

#### Status:

Solved

#### Impact:

Database-level errors (e.g. constraint violations, duplicate keys, malformed queries) can expose column names, constraint names, and query fragments to the client — the same class of information disclosure as the validation-error finding, but via the database layer instead of the validator.

#### Root cause:

In `src/middlewares/error.middleware.ts`, the `QueryFailedError` branch responds with `message: error.message` taken straight from the thrown database error, instead of a generic message.

#### Minimal Fix:

Return a generic error message for `QueryFailedError` (e.g. `"Bad Request"` or `"Could not complete the request"`), and log `error.message` server-side only, mirroring the fix already applied to `validationMiddleware`.

### 4. No Rate Limiting on Authentication Routes

#### Problem:

`/user/signup`, `/user/loginByEmail`, and `/user/loginByUsername` have no rate limiting.

#### Priority

P2

#### Status:

Solved

#### Impact:

Without throttling, these endpoints are open to brute-force credential guessing and credential-stuffing attacks. This is compounded by Finding 1 above (login currently leaks the password hash), since an attacker could pair unlimited login attempts with offline hash cracking on any captured response.

#### Root cause:

No rate-limiting middleware (e.g. `express-rate-limit`) is present anywhere in the codebase or declared in `package.json`, and none of the auth routes in `src/api/users/user.router.ts` have per-route throttling.

#### Minimal Fix:

Add rate limiting (e.g. `express-rate-limit`) to `/user/signup`, `/user/loginByEmail`, and `/user/loginByUsername`, keyed by IP and/or account identifier, with a reasonable window and attempt cap.

## Security

### 1. Validation Error Disclosure

#### Problem:

`validationMiddleware` returned validation details directly in the user response instead of only returning a generic 400 error.

#### Priority

P1

#### Status:

Solved

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

#### Status:

Solved

#### Impact:

Tokens could be issued or accepted under an unintended algorithm if the key material or library defaults changed, weakening token integrity and creating room for algorithm confusion issues.

#### Root cause:

The JWT helper in `src/shared/utils/helpers.ts:57-81` called `jwt.sign(...)` and `jwt.verify(...)` without an explicit `algorithm` allow-list or pinned algorithm setting.

#### Minimal Fix:

Explicitly set the JWT algorithm in `src/shared/utils/helpers.ts:57-81` for both signing and verification, and reject any token whose algorithm does not match the expected allow-list.

### 3. User Password Returned in Response

#### Problem:

`createUser` returned the created user object with its password field still present.

#### Priority:

P1

#### Status:

Solved

#### Impact:

An attacker or client could receive the hashed password for a newly created account, exposing sensitive credential data that should never be sent back in API responses.

#### Root cause:

The service in `src/api/users/user.service.ts:20-25` returned the same `user` object that was passed into `UserRepository.addUser(user)` without stripping the password field before returning it.

#### Minimal Fix:

Return a sanitized user object from `src/api/users/user.service.ts:20-25` that excludes `password` before sending the response, and keep the credential value only in storage.

### 4. User Lookup Selects Full Entity

#### Problem:

`getUserByCredentials` selected the full `user` entity instead of only the columns needed for authentication.

#### Priority:

P1

#### Status:

Solved

#### Impact:

An attacker or internal caller could retrieve more user data than necessary, including the password column, increasing the risk of accidental disclosure in login flows and any downstream code that returns the query result.

#### Root cause:

The repository query in `src/api/users/user.repository.ts:63-72` used `.select('user').from(User, 'user')`, which loads every mapped column instead of an allow-listed subset.

#### Minimal Fix:

Change `src/api/users/user.repository.ts:63-72` to select only the required columns, such as `user_id`, `email`, `username`, and `password` only if the authentication flow truly needs it, and avoid returning the full entity.

### 5. Dynamic Update Key Allows SQL Injection Risk

#### Problem:

`updateUsersBy` built the `WHERE` clause from a dynamic column name, so the query key was not safely constrained.

#### Priority:

P1

#### Status:

Solved

#### Impact:

An attacker who can influence the key could potentially alter the generated SQL and read or modify data outside the intended row filter.

#### Root cause:

The repository code in `src/api/users/user.repository.ts:25-31` interpolated `${key}` directly into `.where(...)` instead of validating the column name against a fixed allow-list before building the query.

#### Minimal Fix:

In `src/api/users/user.repository.ts:25-31`, replace the dynamic key interpolation with a fixed allow-list of permitted columns and keep only the value parameterized.

### 6. Updated Password Can Be Returned in Response

#### Problem:

`updateUser` returned the request body directly, so a password update could be echoed back in the API response.

#### Priority:

P1

#### Status:

Solved

#### Impact:

An attacker or client could receive the updated password value, or its processed form, in the response after changing account details, exposing sensitive credential data that should remain server-side only.

#### Root cause:

The controller in `src/api/users/user.controller.ts:39-44` responded with `updatedUserDetails` from `req.body` instead of returning a sanitized payload that excluded `password`.

#### Minimal Fix:

In `src/api/users/user.controller.ts:39-44`, return a sanitized user object that omits `password` after updates, and keep password handling confined to the service and storage layers.

### 7. Product Create and Update Routes Lack Authorization

#### Problem:

`POST /products` and `PATCH /products/:product_id` were exposed without an authorization check.

#### Priority:

P1

#### Status:

Open

#### Impact:

An unauthenticated or low-privilege user could create new products or modify existing product records if they can reach these endpoints.

#### Root cause:

The router in `src/api/products/product.router.ts:16-31` registered the create and update routes without an authorization middleware before the controller handlers.

#### Minimal Fix:

Add the authorization middleware to `src/api/products/product.router.ts:16-31` before the `POST /` and `PATCH /:product_id` handlers, and restrict those routes to the roles that are allowed to manage products.

### 8. Product Delete Route Lacks Authorization

#### Problem:

`DELETE /products/:product_id` was exposed without an authorization check.

#### Priority:

P1

#### Status:

Open

#### Impact:

An unauthenticated or low-privilege user could delete product records if they can reach the endpoint.

#### Root cause:

The router in `src/api/products/product.router.ts:35-38` registered the delete route without an authorization middleware before the controller handler.

#### Minimal Fix:

Add the authorization middleware to `src/api/products/product.router.ts:35-38` before the `DELETE /:product_id` handler, and restrict the route to the roles that are allowed to remove products.

## Performance

### 1. User Lookup Selects Full Entity

#### Problem:

`getUserByCredentials` selected the full `user` entity instead of only the columns needed for authentication.

#### Priority:

P2

#### Status:

Open

#### Impact:

The database and application transfer unnecessary columns on every login lookup, increasing I/O, memory usage, and response latency.

#### Root cause:

The repository query in `src/api/users/user.repository.ts:63-72` used `.select('user').from(User, 'user')`, which loads every mapped column instead of an allow-listed subset.

#### Minimal Fix:

Change `src/api/users/user.repository.ts:63-72` to select only the columns required by the login flow so the query returns less data and does less work.

### 2. Offset Pagination Does Not Scale for Orders

#### Problem:

`getOrders` used offset-based pagination, which becomes increasingly expensive as the offset grows.

#### Priority:

P3

#### Status:

Open

#### Impact:

As the orders table grows, each request can force the database to walk and discard more earlier rows before returning the requested page, which increases latency and reduces throughput.

#### Root cause:

The repository query in `src/api/orders/order.repository.ts:12-41` applied `.offset(offset).limit(limit)` instead of using cursor or key-based pagination.

#### Minimal Fix:

Replace offset pagination in `src/api/orders/order.repository.ts:12-41` with cursor or key-based pagination so the query advances from the last returned order instead of rescanning from the beginning on every page.

### 3. Order Link Writes Run Sequentially

#### Problem:

`createOrderForGuestUser` and `createOrderForAuthenticatedUser` awaited independent order-link writes one after the other instead of running them in parallel.

#### Priority:

P3

#### Status:

Open

#### Impact:

The order creation flows wait longer than necessary for independent insert operations to finish, which increases request latency.

#### Root cause:

The controller in `src/api/orders/order.controller.ts:18-33` awaited the link creation calls sequentially after the order was created in both order creation handlers.

#### Minimal Fix:

In `src/api/orders/order.controller.ts:18-33`, run the independent link insert operations with `Promise.all` after the order record is created in both handlers so the requests complete faster.

## Reliability

### 1. Order Creation Steps Are Not Atomic

#### Problem:

Order creation, order-product linking, and order-user linking were executed as separate operations without a transaction.

#### Priority:

P2

#### Status:

Open

#### Impact:

If one step fails after the order row is inserted, the database can be left with a partial order or missing relationships, which creates inconsistent order state.

#### Root cause:

The controller in `src/api/orders/order.controller.ts:31-33` called the three order creation steps separately instead of executing them inside one transaction.

#### Minimal Fix:

Wrap the order insert, product link inserts, and user link insert in a single transaction in `src/api/orders/order.controller.ts:31-33` so all three succeed or fail together.
