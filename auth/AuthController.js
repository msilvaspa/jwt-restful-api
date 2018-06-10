const express = require('express')
const bodyParser = require('body-parser')
const jwt = require('jsonwebtoken')
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

router.get('/me', (req, res) => {

  const token = req.headers['x-access-token'];

  if (!token) res.status(401).send({ auth: false, message: 'No token provided.' });

  jwt.verify(token, config.secret, (err, decoded) => {

    if (err) res.status(500).send({ auth: false, message: 'Failed to authenticate token.' });

    User.findById(decoded.id, { password: 0 }, (err, user) => {

      if (err) res.status(500).send('There was a problem finding the user.');
      if (!user) res.status(404).send('No user found.');

      res.status(200).send(user);
    })
  });
});

router.post('/login', (req, res) => {
  User.findOne({ email: req.body.email }, (err, user) => {
    if (err) res.status(500).send('Error on the server.');
    if (!user) res.status(404).send('User not found.');

    const passwordIsValid = bcrypt.compareSync(req.body.password, user.password);

    if (!passwordIsValid) res.status(401).send({ auth: false, token: null });

    const token = jwt.sign({ id: user._id }, config.secret, {
      expiresIn: 86400 //24h
    });
    res.status(200).send({ auth: true, token: token });
  });
});

module.exports = router;