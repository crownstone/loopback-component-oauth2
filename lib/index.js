// Copyright IBM Corp. 2012,2016. All Rights Reserved.
// Node module: loopback-component-oauth2
// This file is licensed under the MIT License.
// License text available at https://opensource.org/licenses/MIT

'use strict';
/**
 * Module dependencies.
 */
var path = require('path');
var SG = require('strong-globalize');
SG.SetRootDir(path.join(__dirname, '..'));
var g = SG();
var loopbackOAuth2 = require('./oauth2-loopback');
var exports = module.exports = loopbackOAuth2;

exports.oAuth2Provider = loopbackOAuth2; // Keep backward-compatibility
exports.oauth2orize = require('./oauth2orize');

/**
 * A factory function for middleware handler that obtains the `authentication`
 * handler configured by the OAuth2 component.
 *
 * @param { Object } [options]   // possible options: { oauthACLgateway : Boolean }
 *                               // if oauthACLgateway is true, we will check if the token provided is a user token.
 *                               //  |_ if the token is a user accesstoken (exists in AccessToken model), we skip oauth authentication
 *                               //  |_ if no token is provided, we skip oauth authentication
 *                               // if it is false, the oauth module will work as normal.
 */
exports.authenticate = function (options) {
  let router;

  // keep track of the tokens we have handled before so we do not need to query for every request.
  return function oauth2AuthenticateHandler(req, res, next) {

    if (!router) {
      let app = req.app;
      let authenticate = app._oauth2Handlers && app._oauth2Handlers.authenticate;
      if (!authenticate) {
        return next(new Error(g.f('The {{OAuth2}} component was not configured for this application.')));
      }

      let handlers = authenticate(options);
      router = app.loopback.Router();
      for (let i = 0, n = handlers.length; i < n; i++) {
        router.use(handlers[i]);
      }
    }

    // if we did not explicitly enable the oauthACLgatewayEnabled option
    let oauthACLgatewayEnabled = options && options.oauthACLgateway || false;
    if (oauthACLgatewayEnabled !== true) {
      return router(req, res, next);
    }

    // if we do not have an access_token, do not use oauth2 to authenticate this request.
    let accessToken = (req && (req.body && req.body.access_token) || (req.query && req.query.access_token)) || null;
    if (!accessToken) {
      next();
      return;
    }

    // we assume the accessToken for oauth is 32 bytes, and the user one is 64 bytes.
    if (accessToken.length > 32) {
      // since user keys are 64 bytes, and the provided token is larger than 32 bytes, we assume this is not an oauth token
      next();
    }
    else {
      // if the token is NOT larger than 32 bytes, we just give it to the oauth handler
      return router(req, res, (err, result) => {

        // in an update of Loopback, ACL has also started using scopes. These are not the OAUTH scopes, but they both bind it to accessToken.scopes
        // if we're in this callback, the oauth part has already detemined that we have access to the requested method based on the oauth scopes.
        // We don't need this anymore and will set it to undefined so the ACL won't refuse service.
        req.accessToken.scopes = undefined
        next(err,result);
      });
    }

    // If we don't want to trust on the size of the tokens, we can check the DB. I don't think this would change any day soon so by not doing this
    // we save ourselves a query.
    // ----------------------
    // let accessTokenModel = req.app.loopback.getModel("AccessToken");
    // // if we use promises insteade of the callback, the context is lost and the loopback-component-access-groups middleware fails to do it's thing.
    // accessTokenModel.findById(accessToken, function (err, token) {
    //   // if the token is not found, it is null. If it is not in the user AccessToken model, we let oauth handle it.
    //   if (token === null || err) {
    //     return router(req, res, next);
    //   }
    //   else {
    //     // the token belongs to a user, we skip the oauth step.
    //     next();
    //   }
    // });
  };
}; 
