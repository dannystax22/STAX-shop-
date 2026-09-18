# STAX Shop — live-ready version

This is a real full-stack starting point, not just a visual mockup.

Included:
- Express backend
- SQLite database
- Customer registration/login
- Secure password hashing with bcrypt
- Signed sessions/tokens
- Products and stock
- Orders
- Customer order history
- Private admin login
- Admin dashboard with customer/order/sales counts
- Responsive STAX Shop storefront

## Run locally
1. Install Node.js 18+.
2. Open this folder in a terminal.
3. Run: npm install
4. Copy `.env.example` to `.env`.
5. Set a strong ADMIN_PASSWORD and SESSION_SECRET.
6. Run: npm start
7. Open: http://localhost:3000

## Before public launch
You still need:
- A hosting account/server
- A domain (e.g. staxshop.com)
- HTTPS
- A production database or persistent disk
- A Nigerian payment gateway account (e.g. Paystack/Flutterwave) and secret keys
- Delivery/returns/privacy/terms setup
- Proper production authentication, rate limiting and backups

The current order endpoint records orders but deliberately does NOT take real money. Do not accept public payments until a payment provider is integrated and tested.

## Important
Never publish the `.env` file or expose admin credentials.
