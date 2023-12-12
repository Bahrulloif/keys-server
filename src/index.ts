import express, { query, response } from "express";
import Sqlite3 from "better-sqlite3";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import cors from "cors";
import axios from "axios";

interface CurrentUser {
  id: number;
  login: string;
  role: string;
  firstName: string;
  lastName: string;
}

const jwtSigningKey =
  "354263@!#^&^*&^*14256341234asdfasdfas5d4654@asdasd@asd!2#$%^&asd";

const port = 9000;
const server = express();
server.use(
  express.json(),
  cors({
    origin: "http://localhost:8080",
  })
);

const db = new Sqlite3("db.sqlite", { verbose: console.log });

const initialTransaction = db.transaction(() => {
  const createUserTable = db.prepare(`
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            first_name VARCHAR(50) NOT NULL,
            last_name VARCHAR(50) NOT NULL,
            login VARCHAR(50) UNIQUE NOT NULL,
            password_hash VARCHAR(60) NOT NULL,
            password_salt VARCHAR(10) NOT NULL,
            role VARCHAR(10) NOT NULL,
            position VARCHAR(255) NOT NULL,
            telephone VARCHAR(15) NOT NULL
        )
    `);
  createUserTable.run();

  const createKeysTable = db.prepare(`
        CREATE TABLE IF NOT EXISTS keys(
            bs_id VARCHAR(4) PRIMARY KEY,
            bs_name VARCHAR(50) NOT NULL,
            bs_address VARCHAR(255) NOT NULL,
            borrow BOOLEAN DEFAULT FALSE
        )
    `);
  createKeysTable.run();

  const createNumberTable = db.prepare(`
  CREATE TABLE IF NOT EXISTS telnumber(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
      tel_number VARCHAR(12) NOT NULL
      
  )
`);
  createNumberTable.run();

  const keysBorrowTable = db.prepare(`
  CREATE TABLE IF NOT EXISTS borrow(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      bs_id VARCHAR(4) NOT NULL,
      bs_name VARCHAR(50) NOT NULL,
      fio VARCHAR(255) NOT NULL,
      borrow_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      return_date TIMESTAMP,
      prichina VARCHAR(255) NOT NULL,
      fio_receiver VARCHAR(255)
  )
`);
  keysBorrowTable.run();

  const admin = db.prepare(`SELECT id FROM users WHERE login = 'admin'`).get();
  if (admin === undefined) {
    const createAdmin = db.prepare(`
            INSERT INTO users(first_name, last_name, login, password_hash, password_salt, role, position, telephone)
            VALUES(
                'Admin',
                'User',
                'admin',
                '$2b$10$YCdjLzjLeCC3qNODNaMKROJUGRvxyjEDWpY./ls5ClC9H8bj7JnVS',
                '$2b$10$YCdjLzjLeCC3qNODNaMKRO',
                'ADMIN',
                'ADMIN',
                '+992411002236'
            )
        `);

    createAdmin.run();
  }
});

initialTransaction.immediate();

server.post("/api/auth/login", (request, response) => {
  const { login, password } = request.body;
  if (typeof login !== "string" || login.trim().length === 0) {
    response.status(400).json({ message: "invalid-login" });
    return;
  }
  if (typeof password !== "string" || password.length === 0) {
    response.status(400).json({ message: "invalid-password" });
    return;
  }

  const user = db.prepare("SELECT * FROM users WHERE login = ?").get(login);
  if (user === undefined) {
    response.status(400).json({ message: "user is undefined" });
    return;
  }
  const passwordHash = bcrypt.hashSync(password, user.password_salt);
  if (passwordHash !== user.password_hash) {
    response.status(400).json({ message: "invalid" });
    return;
  }

  const jwtData: CurrentUser = {
    id: user.id,
    login: user.login,
    role: user.role,
    firstName: user.first_name,
    lastName: user.last_name,
  };
  const token = jwt.sign(jwtData, jwtSigningKey, {
    expiresIn: "30m",
    algorithm: "HS512",
  });

  const responseData = {
    token: token,
    firstName: user.first_name,
    lastName: user.last_name,
    role: user.role,
  };
  response.status(200).json(responseData);
});

function jwtTokenInterceptor(
  request: express.Request,
  response: express.Response,
  next: express.NextFunction
) {
  const token = request.header("Authorization");
  if (token === undefined) {
    response.status(403).json({ message: "unauthenticated" });
    return;
  }
  try {
    const jwtData = jwt.verify(token, jwtSigningKey) as jwt.JwtPayload;
    response.locals.currentUser = {
      id: jwtData.id,
      login: jwtData.login,
      role: jwtData.role,
      firstName: jwtData.firstName,
      lastName: jwtData.lastName,
    } as CurrentUser;
    next();
  } catch (_) {
    response.status(403).json({ message: "invalid-token" });
    return;
  }
}

server.post("/api/manager/create", jwtTokenInterceptor, (request, response) => {
  const currentUser = response.locals.currentUser as CurrentUser;
  if (currentUser.role !== "ADMIN") {
    response.status(403).json({ message: "unauthorized" });
    return;
  }

  const family = request.body.family;
  if (
    typeof family !== "string" ||
    family.trim().length > 50 ||
    family.trim().length === 0
  ) {
    response.status(400).json({ message: "invalid-family" });
    return;
  }
  const name = request.body.name;
  if (
    typeof name !== "string" ||
    name.trim().length > 50 ||
    name.trim().length === 0
  ) {
    response.status(400).json({ message: "invalid-name" });
    return;
  }
  const position = request.body.position;
  if (
    typeof position !== "string" ||
    position.trim().length > 255 ||
    position.trim().length === 0
  ) {
    response.status(400).json({ message: "invalid-position" });
    return;
  }
  const login = request.body.login;
  if (
    typeof login !== "string" ||
    login.trim().length > 50 ||
    login.trim().length === 0
  ) {
    response.status(400).json({ message: "invalid-login" });
    return;
  }

  const password = request.body.password;
  if (typeof password !== "string" || password.length === 0) {
    response.status(400).json({ message: "invalid-password" });
    return;
  }

  const telefon = request.body.telefon;
  if (
    typeof telefon !== "string" ||
    telefon.trim().length > 15 ||
    telefon.trim().length === 0
  ) {
    response.status(400).json({ message: "invalid-telefon" });
    return;
  }

  const transaction = db.transaction(() => {
    const user = db.prepare(`SELECT id FROM users WHERE login=?`).get(login);
    if (user !== undefined) {
      response.status(400).json({ message: "user-exists" });
      return;
    }
    const passwordSalt = bcrypt.genSaltSync(10);
    const passwordHash = bcrypt.hashSync(password, passwordSalt);
    db.prepare(
      `
            INSERT INTO users(first_name, last_name, login, password_hash, password_salt, role, position, telephone)
            VALUES (?, ?, ?, ?, ?, 'MANAGER', ?, ?)
        `
    ).run(
      name.trim(),
      family.trim(),
      login.trim(),
      passwordHash,
      passwordSalt,
      position.trim(),
      telefon.trim()
    );
  });
  transaction.immediate();
  response.json({ message: "ok" });
});

server.get("/api/manager/list", jwtTokenInterceptor, (request, response) => {
  const currentUser = response.locals.currentUser as CurrentUser;
  if (currentUser.role !== "ADMIN") {
    response.status(403).json({ message: "unauthorized" });
    return;
  }

  const managers = db
    .prepare(
      `SELECT id, first_name, last_name, position, login, telephone FROM users WHERE role='MANAGER'`
    )
    .all();
  response.json(managers);
});

server.post(
  "/api/manager/:managId/delete",
  jwtTokenInterceptor,
  (request, response) => {
    const currentUser = response.locals.currentUser as CurrentUser;
    if (currentUser.role !== "ADMIN") {
      response.status(403).json({ message: "unauthorized" });
      return;
    }

    const managId = request.params.managId;

    db.prepare(`DELETE FROM users WHERE id=? AND role='MANAGER'`).run(managId);
    response.json({ message: "ok" });
  }
);

server.post(
  "/api/employee/create",
  jwtTokenInterceptor,
  (request, response) => {
    const currentUser = response.locals.currentUser as CurrentUser;
    if (currentUser.role !== "ADMIN" && currentUser.role !== "MANAGER") {
      response.status(403).json({ message: "unauthorized" });
      return;
    }
    const family = request.body.family;
    if (
      typeof family !== "string" ||
      family.trim().length > 50 ||
      family.trim().length === 0
    ) {
      response.status(400).json({ message: "invalid-family" });
      return;
    }

    const name = request.body.name;
    if (
      typeof name !== "string" ||
      name.trim().length > 50 ||
      name.trim().length === 0
    ) {
      response.status(400).json({ message: "invalid-name" });
      return;
    }

    const position = request.body.position;
    if (
      typeof position !== "string" ||
      position.trim().length > 255 ||
      position.trim().length === 0
    ) {
      response.status(400).json({ message: "invalid-position" });
      return;
    }

    const login = request.body.login;
    if (
      typeof login !== "string" ||
      login.trim().length > 50 ||
      login.trim().length === 0
    ) {
      response.status(400).json({ message: "invalid-login" });
      return;
    }

    const password = request.body.password;
    if (typeof password !== "string" || password.trim().length === 0) {
      response.status(400).json({ message: "invalid-password" });
      return;
    }

    const telefon = request.body.telefon;
    if (
      typeof telefon !== "string" ||
      telefon.trim().length > 15 ||
      telefon.trim().length === 0
    ) {
      response.status(400).json({ message: "invalid-telefon" });
      return;
    }

    const transaction = db.transaction(() => {
      const user = db.prepare(`SELECT id FROM users WHERE login=?`).get(login);
      if (user !== undefined) {
        response.status(400).json({ message: "login-exists" });
        return;
      }
      const passwordSalt = bcrypt.genSaltSync(10);
      const passwordHash = bcrypt.hashSync(password, passwordSalt);
      db.prepare(
        `
    INSERT INTO users (first_name, last_name, login, password_hash, password_salt, role, position, telephone)
    VALUES (?, ?, ?, ?, ?, 'EMPLOYEE', ?, ?)
    `
      ).run(
        name.trim(),
        family.trim(),
        login,
        passwordHash,
        passwordSalt,
        position.trim(),
        telefon.trim()
      );
    });
    transaction.immediate();
    response.json({ message: "ok" });
  }
);

server.get("/api/employee/list", jwtTokenInterceptor, (request, response) => {
  const currentUser = response.locals.currentUser as CurrentUser;
  if (currentUser.role !== "ADMIN" && currentUser.role !== "MANAGER") {
    response.status(403).json({ message: "unauthorized" });
    return;
  }
  const employees = db
    .prepare(
      `SELECT id, first_name, last_name, position, login, telephone FROM users WHERE role='EMPLOYEE'`
    )
    .all();
  response.json(employees);
});

server.post(
  "/api/employee/:empId/delete",
  jwtTokenInterceptor,
  (request, response) => {
    const currentUser = response.locals.currentUser as CurrentUser;
    if (currentUser.role !== "ADMIN" && currentUser.role !== "MANAGER") {
      response.status(403).json({ message: "unauthorized" });
      return;
    }

    const empId = request.params.empId;

    db.prepare(`DELETE FROM users WHERE id=? AND role='EMPLOYEE'`).run(empId);
    response.json({ message: "ok" });
  }
);

server.post("/api/key/create", jwtTokenInterceptor, (request, response) => {
  const currentUser = response.locals.currentUser as CurrentUser;
  if (currentUser.role !== "ADMIN" && currentUser.role !== "MANAGER") {
    response.status(403).json({ message: "unauthorized" });
    return;
  }
  const bsID = request.body.bsID;
  if (typeof bsID !== "string" || bsID.trim().length !== 4) {
    response.status(400).json({ message: "invalid-bsID" });
    return;
  }
  const nameBS = request.body.nameBS;
  if (
    typeof nameBS !== "string" ||
    nameBS.trim().length > 50 ||
    nameBS.trim().length === 0
  ) {
    response.status(400).json({ message: "invalid-nameBS" });
    return;
  }

  const addressBS = request.body.addressBS;
  if (
    typeof addressBS !== "string" ||
    addressBS.trim().length > 255 ||
    addressBS.trim().length === 0
  ) {
    response.status(400).json({ message: "invalid-addressBS" });
    return;
  }
  const transaction = db.transaction(() => {
    const result = db.prepare(`SELECT bs_id FROM keys WHERE bs_id=?`).get(bsID);
    if (result !== undefined) {
      response.status(400).json({ message: "key-exists" });
      return;
    }

    db.prepare(
      `INSERT INTO keys (bs_id, bs_name, bs_address) VALUES (?,?,?)`
    ).run(bsID, nameBS, addressBS);
  });
  transaction.immediate();
  response.json({ message: "ok" });
});

server.get("/api/key/list", jwtTokenInterceptor, (request, response) => {
  const currentUser = response.locals.currentUser as CurrentUser;
  if (currentUser.role !== "ADMIN" && currentUser.role !== "MANAGER") {
    response.status(403).json({ message: "unauthorized" });
    return;
  }
  const keys = db.prepare(`SELECT bs_id, bs_name, bs_address FROM keys`).all();
  response.json(keys);
});

server.post(
  "/api/key/:bsId/delete",
  jwtTokenInterceptor,
  (request, response) => {
    const currentUser = response.locals.currentUser as CurrentUser;
    if (currentUser.role !== "ADMIN" && currentUser.role !== "MANAGER") {
      response.status(403).json({ message: "unauthorized" });
      return;
    }

    const bsId = request.params.bsId;

    db.prepare(`DELETE FROM keys WHERE bs_id=?`).run(bsId);
    response.json({ message: "ok" });
  }
);

server.post("/api/keys/search", jwtTokenInterceptor, (request, response) => {
  const search = request.body.search;

  if (
    typeof search !== "string" ||
    search.trim().length > 100 ||
    search.trim().length == 0
  ) {
    response.status(400).json({ message: "invalid-Search" });
    return;
  }
  const result = db
    .prepare(
      `SELECT bs_id, bs_name, borrow FROM keys WHERE bs_id=? OR LOWER(bs_name) LIKE ?`
    )
    .all(search, `%${search.toLowerCase()}%`);
  response.send(result);
});

server.post("/api/table/borrow", jwtTokenInterceptor, (request, response) => {
  const idKey = request.body.bs_id;
  const prichina = request.body.prichina;
  if (prichina === "") {
    response.status(400).json({ message: "required string" });
    return;
  }
  const transaction = db.transaction(() => {
    const keyBool = db
      .prepare(`SELECT borrow, bs_name FROM keys WHERE bs_id=?`)
      .get(idKey);
    console.log("idKey", idKey);
    console.log("prichina", prichina);
    console.log("keyBool", keyBool);
    if (keyBool.borrow === 1) {
      response.status(400).json({ message: "Key is borrowed" });
      return undefined;
    }
    const currentUser = response.locals.currentUser as CurrentUser;
    const nAME = currentUser.firstName + " " + currentUser.lastName;
    console.log("nAME", nAME);
    db.prepare(
      `INSERT INTO borrow(bs_id, bs_name, prichina, fio) VALUES (?, ?, ?, ?)`
    ).run(idKey, keyBool.bs_name, prichina, nAME);
    db.prepare(`UPDATE keys SET borrow =? WHERE bs_id=?`).run(1, idKey);
    return { fio: nAME, bsID: idKey, nameBS: keyBool.bs_name };
  });

  const result = transaction.immediate();
  if (result !== undefined) {
    smsSender(true, result.fio, result.bsID, result.nameBS);
  }
  response.json({ message: "ok" });
});

server.post("/api/table/receiver", jwtTokenInterceptor, (request, response) => {
  const idKey = request.body.bsId;
  const transaction = db.transaction(() => {
    const keyBool = db
      .prepare(`SELECT borrow, bs_name FROM keys WHERE bs_id=?`)
      .get(idKey);
    if (keyBool.borrow === 0) {
      response.status(400).json({ message: "Key is received" });
      return undefined;
    }
    const currentUser = response.locals.currentUser as CurrentUser;
    const fioReceiver = currentUser.firstName + " " + currentUser.lastName;
    console.log("idKey", idKey);
    console.log("keyBool.borrow", keyBool.borrow);
    console.log("fioReceiver", fioReceiver);
    const employeeFio = db
      .prepare(`SELECT fio FROM borrow WHERE bs_id=? AND return_date IS NULL`)
      .get(idKey);
    db.prepare(
      `UPDATE borrow SET fio_receiver=?, return_date=CURRENT_TIMESTAMP WHERE bs_id=? AND return_date IS NULL`
    ).run(fioReceiver, idKey);
    db.prepare(`UPDATE keys SET borrow =? WHERE bs_id=?`).run(0, idKey);
    return { fio: employeeFio.fio, bsID: idKey, nameBS: keyBool.bs_name };
  });

  const result = transaction.immediate();
  if (result !== undefined) {
    smsSender(false, result.fio, result.bsID, result.nameBS);
  }
  response.json({ message: "ok" });
});

server.post("/api/table", jwtTokenInterceptor, (request, response) => {
  const searchFio = request.body.name;
  const searchBsId = request.body.bsId;
  const searchBeginDateTime = request.body.beginDateTime;
  const searchEndDateTime = request.body.endDateTime;
  const keyBool = request.body.keyBool;

  let search = "";
  const params: any[] = [];

  if (
    typeof searchFio === "string" &&
    searchFio.trim().length > 0 &&
    searchFio.trim().length < 100
  ) {
    search = search + " LOWER(fio) LIKE ? ";
    params.push("%" + searchFio.toLowerCase() + "%");
  }
  if (
    typeof searchBsId === "string" &&
    searchBsId.trim().length > 0 &&
    searchBsId.trim().length < 100
  ) {
    if (search.length > 0) {
      search = search + " AND ";
    }
    search = search + " (LOWER(bs_name) LIKE ? OR bs_id = ?) ";
    params.push("%" + searchBsId.toLowerCase() + "%", searchBsId);
  }

  if (
    typeof searchBeginDateTime === "string" &&
    searchBeginDateTime.trim().length > 0
  ) {
    if (search.length > 0) {
      search = search + " AND ";
    }
    search = search + " borrow_date>=? ";
    params.push(searchBeginDateTime);
  }

  if (
    typeof searchEndDateTime === "string" &&
    searchEndDateTime.trim().length > 0
  ) {
    if (search.length > 0) {
      search = search + " AND ";
    }
    search = search + " borrow_date<=? ";
    params.push(searchEndDateTime);
  }

  if (keyBool === true) {
    if (search.length > 0) {
      search = search + " AND ";
    }
    search = search + " return_date is NULL ";
  }

  let query =
    "SELECT id, bs_id, bs_name, fio, borrow_date, return_date, prichina, fio_receiver FROM borrow";
  if (search.length > 0) {
    query = query + " WHERE " + search;
  }

  const table = db.prepare(query).all(...params);
  const result = table.map((e) => {
    return {
      ...e,
      borrow_date: new Date(e.borrow_date),
      return_date: e.return_date ? new Date(e.return_date) : undefined,
    };
  });
  response.json(result);
});

// server.post("/api/table/search", jwtTokenInterceptor, (request, response) => {
//   const searchFio = request.body.name;
//   const searchBsId = request.body.bsId;
//   const searchBeginTime = request.body.begintime;
//   const searchBeginDate = request.body.begindate;
//   const searchEndTime = request.body.endtime;
//   const searchEndDate = request.body.enddate;

//   if (
//     typeof searchFio === "string" ||
//     searchFio.trim().length < 100 ||
//     searchFio.trim().length !== 0
//   ) {

//     response.status(400).json({ message: "invalid-Search" });
//     return;
//   }
//   if (
//     typeof searchBsId !== "string" ||
//     searchBsId.trim().length > 100 ||
//     searchBsId.trim().length == 0
//   ) {
//     response.status(400).json({ message: "invalid-Search" });
//     return;
//   }
//   const result = db
//     .prepare(
//       `SELECT id, bs_id, bs_name, fio, borrow_date, return_date, prichina, fio_receiver FROM borrow
// WHERE bs_id=? OR LOWER(bs_name) OR fio OR borrow_date OR return_date LIKE ?`
//     )
//     .all(
//       searchBsId,
//       `%${searchBsId.toLowerCase()}%`,
//       searchFio,
//       searchBeginDate,
//       searchEndDate
//     );
//   response.send(result);
// });

// let search = "";
// const params = [];

// if (
//   typeof searchFio === "string" &&
//   (searchFio.trim().length > 0) && (searchFio.trim().length < 100)
// ) {
//   (search = search + " LOWER(fio) LIKE ? "), params.push('%' + searchFio.toLowerCase() + '%');
// }

// if (
//   typeof searchBsId === "string" &&
//   (searchBsId.trim().length > 0) && (searchBsId.trim().length < 100)
// ) {
//   if (search.length > 0) {
//     search = search + " AND ";
//   }
//   (search = search + " LOWER(bs_name) LIKE ? "), params.push(searchBsId);
// }
//
// if (search.length > 0) {
//   search = search + " WHERE " + search;
// }
// if (searchBeginTime!==0){
//  if (query.length>0){
//    search=search+" AND ";
//     }
//      (search=search+ " borrow_date LIKE ? "), params.push(searchBeginTime);
//   }
//
//if (searchBeginDate!==0){
//   if (query.length>0){
//     search=search+ " AND ";
//   }
//   (search=search+ " borrow_date LIKE ? "), params.push(searchBeginDate);
// }
// if (searchEndTime!==0){
//   if (query.length>0){
//     search=search+ " AND ";
//   }
//   (search=search+ " return_date LIKE ? "), params.push(searchEndTime);
// }
//
//if (searchEndDate!==0){
//   if (query.length>0){
//     search=search+ " AND ";
//   }
//   (search=search+ " return_date LIKE ? "), params.push(searchEndDate);
// }
//
//
//
// let query = "SELECT .... FROM borrow";
// if (search.length > 0) {
//   query = query + " WHERE " + search;
// }
//

// db.prepare(query).all(...params);

server.post("/api/profile/update", jwtTokenInterceptor, (request, response) => {
  const currentUser = response.locals.currentUser as CurrentUser;

  const family = request.body.family;
  if (
    typeof family !== "string" ||
    family.trim().length > 50 ||
    family.trim().length === 0
  ) {
    response.status(400).json({ message: "invalid-family" });
    return;
  }
  const name = request.body.name;
  if (
    typeof name !== "string" ||
    name.trim().length > 50 ||
    name.trim().length === 0
  ) {
    response.status(400).json({ message: "invalid-name" });
    return;
  }
  const position = request.body.position;
  if (
    typeof position !== "string" ||
    position.trim().length > 255 ||
    position.trim().length === 0
  ) {
    response.status(400).json({ message: "invalid-position" });
    return;
  }
  const login = request.body.login;
  if (
    typeof login !== "string" ||
    login.trim().length > 50 ||
    login.trim().length === 0
  ) {
    response.status(400).json({ message: "invalid-login" });
    return;
  }

  const telefon = request.body.telefon;
  if (
    typeof telefon !== "string" ||
    telefon.trim().length > 15 ||
    telefon.trim().length === 0
  ) {
    response.status(400).json({ message: "invalid-telefon" });
    return;
  }

  const transaction = db.transaction(() => {
    if (currentUser.login !== login) {
      const user = db.prepare(`SELECT id FROM users WHERE login=?`).get(login);
      if (user !== undefined) {
        response.status(400).json({ message: "user-exists" });
        return;
      }
    }

    db.prepare(
      `UPDATE users SET first_name=?, last_name=?, login=?, position=?, telephone=? WHERE id=?`
    ).run(
      name.trim(),
      family.trim(),
      login.trim(),
      position.trim(),
      telefon.trim(),
      currentUser.id
    );
    const password = request.body.password;
    if (typeof password === "string" && password.length > 0) {
      const passwordSalt = bcrypt.genSaltSync(10);
      const passwordHash = bcrypt.hashSync(password, passwordSalt);
      db.prepare(
        `UPDATE users SET password_hash=?, password_salt=? WHERE id=?`
      ).run(passwordHash, passwordSalt, currentUser.id);
    }
  });
  transaction.immediate();
  response.json({ message: "ok" });
});

server.get("/api/profile/get", jwtTokenInterceptor, (request, response) => {
  const currentUser = response.locals.currentUser as CurrentUser;

  const user = db
    .prepare(
      `SELECT first_name, last_name, position, login, telephone FROM users WHERE id=?`
    )
    .get(currentUser.id);
  response.json(user);
});

server.post("/api/smssender", jwtTokenInterceptor, (request, response) => {
  const currentUser = response.locals.currentUser as CurrentUser;
  if (currentUser.role !== "ADMIN" && currentUser.role !== "MANAGER") {
    response.status(403).json({ message: "unauthorized" });
    return;
  }
  const telNumber = request.body.telNumber;
  const transaction = db.transaction(() => {
    const result = db
      .prepare(`SELECT tel_number FROM telnumber WHERE tel_number=?`)
      .get(telNumber);
    if (result !== undefined) {
      response.status(400).json({ message: "number-exists" });
      return;
    }

    db.prepare(`INSERT INTO telnumber (tel_number) VALUES (?)`).run(telNumber);
  });
  transaction.immediate();
  response.json({ message: "ok" });
});

server.post(
  "/api/number/:id/delete",
  jwtTokenInterceptor,
  (request, response) => {
    const currentUser = response.locals.currentUser as CurrentUser;
    if (currentUser.role !== "ADMIN" && currentUser.role !== "MANAGER") {
      response.status(403).json({ message: "unauthorized" });
      return;
    }

    const id = request.params.id;

    db.prepare(`DELETE FROM telnumber WHERE id=?`).run(id);
    response.json({ message: "ok" });
  }
);

server.get("/api/smssender/list", jwtTokenInterceptor, (request, response) => {
  const currentUser = response.locals.currentUser as CurrentUser;
  if (currentUser.role !== "ADMIN" && currentUser.role !== "MANAGER") {
    response.status(403).json({ message: "unauthorized" });
    return;
  }
  const numberList = db.prepare(`SELECT id, tel_number FROM telnumber`).all();
  response.json(numberList);
});

const options: Intl.DateTimeFormatOptions = {
  year: "numeric",
  month: "2-digit",
  day: "2-digit",
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hour12: false,
};

async function smsSender(
  isTake: boolean,
  fio: string,
  bsID: string,
  nameBS: string
) {
  const date = new Date().toLocaleDateString(
    ["tj-TJ", "ru-RU", "en-US"],
    options
  );
  const listNum = db.prepare(`SELECT tel_number FROM telnumber`).all();
  let smsText: string;
  if (isTake === true) {
    smsText = `${fio} ВЗЯЛ ключи от ${bsID}_${nameBS} в ${date}`;
  } else {
    smsText = `${fio} СДАЛ ключи от ${bsID}_${nameBS} в ${date}`;
  }
  smsText = encodeURIComponent(smsText);
  try {
    await Promise.all(
      listNum.map((num) => {
        return axios.get(
          `http://10.241.208.92:8095/MegaKey?USER=OTU&PASS=otu2023&SENDER=MegaFonKeys&NUMBER=${num.tel_number}&TEXT=${smsText}`
        );
      })
    );
  } catch (e) {}
}

server.listen(port, () => {
  console.log(`Server started on port ${port}`);
});
