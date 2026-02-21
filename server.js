{
  "name": "morechat",
  "version": "1.0.0",
  "description": "Private messenger with admin panel",
  "main": "server.js",
  "scripts": {
    "start": "node server.js",
    "dev": "nodemon server.js"
  },
  "dependencies": {
    "express": "^4.18.2",
    "socket.io": "^4.7.2",
    "better-sqlite3": "^9.4.3",
    "bcryptjs": "^2.4.3",
    "express-session": "^1.17.3",
    "connect-sqlite3": "^0.9.13"
  }
}
