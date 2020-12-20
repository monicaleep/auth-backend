const config = require('../config/auth.config')
const db = require('../models/index')
// access to our db through user and role
const User = db.user;
const Role = db.role

// this will give us access to encode and decode the jwt itself
const jwt = require('jsonwebtoken')
// for hashing out passwords
const bcrypt = require('bcryptjs')


//this will handle sign up
exports.signup = (req,res) => {
  // we are going to make our user object using paramms from req
  const user = new User({
    username: req.body.username,
    email: req.body.email,
    password: bcrypt.hashSync(req.body.password, 8)
  })
  user.save((err,user)=>{
    if(err){
      res.status(500).send({message: 'Error signing up user'+err})
      return
    }
    // we check if roles were passed on req.body
    if(req.body.roles){
      Role.find({
        name: {$in: req.body.roles}
      },(err,roles) => {
        if(err){
          res.status(500).send({message: err})
          return
        }
        // pass roles from the request
        user.roles = roles.map(role=>role._id)

        user.save(err=>{
          if(err){
            res.status(500).send({message:err})
          }
          res.send({message:"User created successfully"})
        })
      })
    } else {
      // default: user that doesn't pass roles gets a user role
      Role.findOne({name:"user"},(err,role)=>{
        if(err){
          res.status(500).send({message:err})
          return
        }
        user.roles = [role._id]
        user.save(err=>{
          if(err){
            res.status(500).send({message:err})
            return
          }
          res.send("User was registered successfully")
        })
      })
    }

  })
}


exports.signin = (req,res) => {
  User.findOne({
    username: req.body.username
  })
  // populates values from the roles id we stored in the document
  .populate('roles',"-__v")
  // exec returning our user
  .exec((err, user) => {
    if(err){
      res.status(500).send({message:err})
      return
    }
    //user did not exist
    if(!user){
      res.status(404).send({message: "User not found"})
      return
    }
    // validate the password via bcrypt
    const passwordIsValid = bcrypt.compareSync(req.body.password, user.password)
    // if password not valid, let the user know
    if(!passwordIsValid){
      return res.status(401).send({accessToken: null, message: "invalid password"})
    }
    // if password is valid, generate a token
    const token = jwt.sign({id:user._id},config.secret,{
      expiresIn: 86400 // expires today in 24 hours (in seconds)
    })
    // setting roles to pass back in our response
    let authorities = [];
    for (let i =0;i<user.roles.length;i++){
      authorities.push("ROLE_" + user.roles[i].name.toUpperCase())
    }

    res.status(200).send({
      id: user._id,
      username: user.username,
      email: user.email,
      roles: authorities,
      accessToken: token
    })
  })
}
