var app = require('./app');
var PORT = process.env.PORT || 3000;

var server = app.listen(PORT, () => {
  console.log(`Listening on port: ${PORT}`);
});