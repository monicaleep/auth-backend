const { verifySignup } = require('../middleware')
const controller = require('../controllers/auth.controller.js')

module.exports = function(app) {
  app.use((req,res,next)=>{
    res.header(
      // set header and allow use of x access token
      'Access-Control-Allow-Headers',
      'x-access-token, Origin, Content-type, Accept'
    );next()
  })

  app.post('/api/auth/signup',
  [verifySignup.checkDuplicateUsernameOrEmail,
    verifySignup.checkRolesExisted],
    controller.signup
  )

  app.post('/api/auth/signin', controller.signin)
}
