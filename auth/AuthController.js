const express = require('express')
const bodyParser = require('body-parser')
const jwt = require('jwt')
const bcrypt = require('bcryptjs')
const User = require('../user/User')
const config = require('../config')
const router = express.Router()

router.use(bodyParser.urlencoded({ extended: false }))
router.use(bodyParser.json())

router.post('/register', (req, res) => {
  const hashedPassword = bcrypt.hashSync(req.body.password, 8);

  User.create({
    name: req.body.name,
    email: req.body.email,
    password: req.body.password
  },
    (err, user) => {
      if (err) res.status(500).send("There was a problem registering the user.");

      const token = jwt.sign({ id: user._id }, config.secret, {
        expiresIn: 86400 //24h
      })
      res.status(200).send({ auth: true, token: token })
    });
});