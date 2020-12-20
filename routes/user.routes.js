const { authJwts} = require('../middleware')
const controller = require('../controllers/user.controller')


module.exports = function(app){
  app.use((req,res,next)=>{
    res.header(
      // set header and allow use of x access token
      'Access-Control-Allow-Headers',
      'x-access-token, Origin, Content-type, Accept'
    );next()
  })

  app.get('/api/test/all',controller.allAccess)

  app.get('/api/test/user', [authJwts.verifyWebToken],controller.userBoard)

  app.get('/api/test/admin',[authJwts.verifyWebToken, authJwts.isAdmin], controller.adminBoard)

}
