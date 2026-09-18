
require("dotenv").config();
const express = require("express");
const path = require("path");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const app = express();

const PORT = process.env.PORT || 3000;
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || "admin@staxshop.local";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "CHANGE_THIS_ADMIN_PASSWORD";
const SESSION_SECRET = process.env.SESSION_SECRET || "CHANGE_THIS_SESSION_SECRET";

if (ADMIN_PASSWORD === "CHANGE_THIS_ADMIN_PASSWORD" || SESSION_SECRET === "CHANGE_THIS_SESSION_SECRET") {
  console.warn("WARNING: Set ADMIN_PASSWORD and SESSION_SECRET in .env before production.");
}

const db = new Database(process.env.DB_PATH || path.join(__dirname, "stax.db"));
db.pragma("journal_mode = WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  contact TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS products (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  price INTEGER NOT NULL,
  category TEXT NOT NULL,
  icon TEXT NOT NULL,
  stock INTEGER NOT NULL DEFAULT 0,
  active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS orders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  order_code TEXT NOT NULL UNIQUE,
  user_id INTEGER,
  customer_name TEXT NOT NULL,
  phone TEXT NOT NULL,
  address TEXT NOT NULL,
  total INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'Pending',
  created_at TEXT NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS order_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  order_id INTEGER NOT NULL,
  product_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  price INTEGER NOT NULL,
  quantity INTEGER NOT NULL,
  FOREIGN KEY(order_id) REFERENCES orders(id),
  FOREIGN KEY(product_id) REFERENCES products(id)
);
`);

const count = db.prepare("SELECT COUNT(*) c FROM products").get().c;
if (!count) {
  const seed = db.prepare("INSERT INTO products(name,price,category,icon,stock) VALUES (?,?,?,?,?)");
  const products = [
    ["Wireless Earbuds",12500,"Electronics","🎧",50],
    ["Men's Sneakers",18000,"Shoes","👟",35],
    ["Smart Watch",25000,"Gadgets","⌚",25],
    ["Women's Dress",16500,"Fashion","👗",40],
    ["Men's Hoodie",14500,"Fashion","🧥",30],
    ["Backpack",12000,"Fashion","🎒",30],
    ["Bluetooth Speaker",22000,"Electronics","🔊",25],
    ["Phone Case",4500,"Phones & Accessories","📱",80]
  ];
  const tx = db.transaction(() => products.forEach(p => seed.run(...p)));
  tx();
}

app.use(express.json({limit:"1mb"}));
app.use(express.urlencoded({extended:true}));
app.use(express.static(path.join(__dirname,"public")));

function sign(payload) {
  const data = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const sig = crypto.createHmac("sha256", SESSION_SECRET).update(data).digest("base64url");
  return `${data}.${sig}`;
}
function verify(token) {
  try {
    const [data,sig] = token.split(".");
    const expected = crypto.createHmac("sha256", SESSION_SECRET).update(data).digest("base64url");
    if (!crypto.timingSafeEqual(Buffer.from(sig),Buffer.from(expected))) return null;
    const p = JSON.parse(Buffer.from(data,"base64url").toString());
    if (p.exp < Date.now()) return null;
    return p;
  } catch { return null; }
}
function auth(req,res,next){
  const p = verify((req.headers.authorization||"").replace("Bearer ",""));
  if(!p) return res.status(401).json({error:"Please log in."});
  req.user=p; next();
}
function admin(req,res,next){
  const p = verify((req.headers.authorization||"").replace("Bearer ",""));
  if(!p || p.role!=="admin") return res.status(401).json({error:"Admin access required."});
  req.user=p; next();
}

app.post("/api/register", async (req,res)=>{
  const {name,contact,password}=req.body;
  if(!name || !contact || !password || password.length<6) return res.status(400).json({error:"Name, contact and a password of at least 6 characters are required."});
  try{
    const hash=await bcrypt.hash(password,12);
    const info=db.prepare("INSERT INTO users(name,contact,password_hash,created_at) VALUES(?,?,?,?)")
      .run(name.trim(),contact.trim(),hash,new Date().toISOString());
    const token=sign({id:info.lastInsertRowid,role:"customer",exp:Date.now()+1000*60*60*24*7});
    res.json({token,user:{id:info.lastInsertRowid,name,contact}});
  }catch(e){res.status(409).json({error:"That phone/email is already registered."});}
});

app.post("/api/login", async (req,res)=>{
  const {contact,password}=req.body;
  const u=db.prepare("SELECT * FROM users WHERE contact=?").get((contact||"").trim());
  if(!u || !(await bcrypt.compare(password||"",u.password_hash))) return res.status(401).json({error:"Invalid login details."});
  const token=sign({id:u.id,role:"customer",exp:Date.now()+1000*60*60*24*7});
  res.json({token,user:{id:u.id,name:u.name,contact:u.contact}});
});

app.post("/api/admin/login", (req,res)=>{
  const {email,password}=req.body;
  if(email!==ADMIN_EMAIL || password!==ADMIN_PASSWORD) return res.status(401).json({error:"Invalid admin login."});
  res.json({token:sign({role:"admin",exp:Date.now()+1000*60*60*8})});
});

app.get("/api/products",(req,res)=>{
  const q=(req.query.q||"").trim();
  const rows=q
    ? db.prepare("SELECT * FROM products WHERE active=1 AND (name LIKE ? OR category LIKE ?) ORDER BY id DESC").all(`%${q}%`,`%${q}%`)
    : db.prepare("SELECT * FROM products WHERE active=1 ORDER BY id DESC").all();
  res.json(rows);
});

app.get("/api/me",auth,(req,res)=>{
  if(req.user.role==="admin") return res.json({role:"admin"});
  const u=db.prepare("SELECT id,name,contact,created_at FROM users WHERE id=?").get(req.user.id);
  res.json({role:"customer",user:u});
});

app.post("/api/orders",auth,(req,res)=>{
  if(req.user.role!=="customer") return res.status(403).json({error:"Customers only."});
  const {name,phone,address,items}=req.body;
  if(!name||!phone||!address||!Array.isArray(items)||!items.length) return res.status(400).json({error:"Complete customer and cart details are required."});
  const tx=db.transaction(()=>{
    let total=0, checked=[];
    for(const item of items){
      const p=db.prepare("SELECT * FROM products WHERE id=? AND active=1").get(Number(item.productId));
      const qty=Math.max(1,Number(item.quantity)||1);
      if(!p) throw new Error("A product is no longer available.");
      if(p.stock<qty) throw new Error(`${p.name} does not have enough stock.`);
      total += p.price*qty;
      checked.push({p,qty});
    }
    const code="STX-"+crypto.randomBytes(4).toString("hex").toUpperCase();
    const o=db.prepare("INSERT INTO orders(order_code,user_id,customer_name,phone,address,total,created_at) VALUES(?,?,?,?,?,?,?)")
      .run(code,req.user.id,name,phone,address,total,new Date().toISOString());
    const oi=db.prepare("INSERT INTO order_items(order_id,product_id,name,price,quantity) VALUES(?,?,?,?,?)");
    const dec=db.prepare("UPDATE products SET stock=stock-? WHERE id=?");
    checked.forEach(({p,qty})=>{oi.run(o.lastInsertRowid,p.id,p.name,p.price,qty);dec.run(qty,p.id);});
    return {code,total};
  });
  try{res.json(tx());}catch(e){res.status(400).json({error:e.message});}
});

app.get("/api/my-orders",auth,(req,res)=>{
  if(req.user.role!=="customer") return res.json([]);
  const orders=db.prepare("SELECT id,order_code,total,status,created_at FROM orders WHERE user_id=? ORDER BY id DESC").all(req.user.id);
  res.json(orders);
});

app.get("/api/admin/stats",admin,(req,res)=>{
  const customers=db.prepare("SELECT COUNT(*) c FROM users").get().c;
  const orders=db.prepare("SELECT COUNT(*) c FROM orders").get().c;
  const sales=db.prepare("SELECT COALESCE(SUM(total),0) s FROM orders").get().s;
  const products=db.prepare("SELECT COUNT(*) c FROM products WHERE active=1").get().c;
  res.json({customers,orders,sales,products});
});
app.get("/api/admin/customers",admin,(req,res)=>{
  res.json(db.prepare("SELECT id,name,contact,created_at FROM users ORDER BY id DESC").all());
});
app.get("/api/admin/orders",admin,(req,res)=>{
  res.json(db.prepare("SELECT id,order_code,customer_name,phone,address,total,status,created_at FROM orders ORDER BY id DESC").all());
});
app.patch("/api/admin/orders/:id",admin,(req,res)=>{
  const allowed=["Pending","Paid","Processing","Shipped","Delivered","Cancelled"];
  if(!allowed.includes(req.body.status)) return res.status(400).json({error:"Invalid status"});
  db.prepare("UPDATE orders SET status=? WHERE id=?").run(req.body.status,req.params.id);
  res.json({ok:true});
});

app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));
app.listen(PORT,()=>console.log(`STAX Shop running on http://localhost:${PORT}`));
