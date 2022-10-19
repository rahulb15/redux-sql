const express = require('express');
const router = express.Router();
const db = require('../models');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
// const { check, validationResult } = require('express-validator');
const { validateToken } = require('../middlewares/AithMiddleware.js');
const UserController = require('../controllers/userController.js');


router.post('/register', UserController.register);
router.post('/login', UserController.login);
router.get('/getUser', validateToken, UserController.getUser);
router.get('/getAllUsers', UserController.getAllUsers);




module.exports = router;
