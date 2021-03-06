const express = require('express');
const bodyParser = require('body-parser')
const dbConfig = require('./config/db.config.js')
const cors = require('cors')
const app = express();

app.use(cors())
// parse requests of content-type application/json
app.use(bodyParser.json())

// parse request of content-type application/x-www-form-urlencoded
app.use(bodyParser.urlencoded({extended: true}))

// set up mongoose
const db = require('./models/index.js')
const Role = db.role

db.mongoose
  .connect(`mongodb://${dbConfig.HOST}:${dbConfig.PORT}/${dbConfig.DB}`,{
    useNewUrlParser: true,
    useUnifiedTopology: true
})
  .then(()=>{
    console.log('Successfully connected to MongoDB')
    initial()
  })
  .catch(err=>{
    console.error("connection error",err)
    process.exit()
  })


//simple route, do I work?
app.get('/',(req,res)=>{
  res.json({message:"Welcome to the home page"})
})

// import the routes we wrote
require('./routes/auth.routes')(app)
require('./routes/user.routes')(app)


// set the port, listen
const PORT = process.env.PORT || 8080
app.listen(PORT,()=>{
  console.log(`Server running on ${PORT}`)
})


function initial() {
  Role.estimatedDocumentCount((err, count) => {
    if (!err && count === 0) {
      new Role({
        name: "user"
      }).save(err => {
        if (err) {
          console.log("error", err);
        }
        console.log("added 'user' to roles collection");
      });
      new Role({
        name: "admin"
      }).save(err => {
        if (err) {
          console.log("error", err);
        }
        console.log("added 'admin' to roles collection");
      });
    }
  });
}
