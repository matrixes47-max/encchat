# enc.chat

Zero-knowledge encrypted anonymous chat.

## უსაფრთხოება

- **AES-256-GCM** დაშიფვრა — client-side, სერვერი ვერ კითხულობს
- **PBKDF2** (100,000 iteration) — პაროლის brute-force დაცვა
- **Zero-Knowledge** — სერვერს პაროლი არ ეგზავნება
- **No IP logging** — IP არ ინახება
- **Auto-delete** — TTL-ის შემდეგ სრულად იშლება სერვერიდან
- **In-memory** — DB არ არის, სერვერის restart = ყველაფერი ქრება

## გაშვება (Railway)

1. [railway.app](https://railway.app) — შექმენი ანგარიში
2. "New Project" → "Deploy from GitHub repo"
3. ეს repo ატვირთე GitHub-ზე და დაუკავშირე Railway-ს
4. Railway ავტომატურად გაუშვებს `npm start`-ს
5. Settings → Networking → Generate Domain → მზადაა!

## ლოკალური გაშვება

```bash
npm install
npm start
```

გახსენი: http://localhost:3000

## სტრუქტურა

```
enc.chat/
├── server.js        ← Node.js backend (Express)
├── package.json
├── .gitignore
└── public/
    └── index.html   ← Frontend (crypto სრულად აქ)
```
