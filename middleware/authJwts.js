const jwt = require('jsonwebtoken')
const config = require('../config/auth.config.js')
const db = require('../models/index.js')
const User = db.user;
const Role = db.role;

verifyWebToken = (req,res,next) => {
  // first we declare our token which is passed in our header
  let token = req.headers['x-access-token']
  //if no token given we respond with an error
  if (!token){
    return res.status(403).send({message: 'No token provided'})
  }
  // we try to verify the token
  jwt.verify(token, config.secret, (err, decoded)=>{
    if(err){
      return res.status(401).send({message:"Unauthorized"})
    }
    // set user id to decoded id
    req.userId = decoded.id;
    next()
  })
}

//  function to verify if admin or not
isAdmin = (req,res,next) => {
  User.findOne({_id:req.userId}).exec((err,user)=>{
    // throw and error if this user does not exist (cannot find user)
    if(err){
      return res.status(500).send({message:err})
    }
    // find user's role if the user exists
    Role.find({
      _id :{ $in: user.roles }
    }, (err,roles)=>{
      //user probably doesn't exist
      if(err){
        return res.status(500).send({message:err})
      }
      // loop thru the roles and check if there's an admin role
      for (let i=0;i<roles.length;i++){
        if(roles[i].name==='admin'){
          next()
          return
        }
      }
      // if no admin role found, send status 403 message
      return res.status(403).send({message: "Requires admin role"})
    })
  })
}

const authJwt = {
  verifyWebToken,
  isAdmin
}

module.exports = authJwt;
