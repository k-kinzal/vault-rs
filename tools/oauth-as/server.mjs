// Real oidc-provider Authorization Server, with synthetic login ONLY for integration tests.
// Never run this interaction handler as a production identity service.
import Provider from 'oidc-provider';
import {generateKeyPairSync, ECDH, randomBytes} from 'node:crypto';
import fs from 'node:fs';
import https from 'node:https';
const c=JSON.parse(fs.readFileSync(process.argv[2],'utf8'));
if(c.test_fixture!==true) throw new Error('test fixture opt-in required');
const {privateKey,publicKey}=generateKeyPairSync('ec',{namedCurve:'P-256'});
const jwk=privateKey.export({format:'jwk'});jwk.kid='integration-as';jwk.alg='ES256';jwk.use='sig';
const pub=publicKey.export({format:'jwk'});
const point=Buffer.concat([Buffer.from([4]),Buffer.from(pub.x,'base64url'),Buffer.from(pub.y,'base64url')]);
const issuer=`https://localhost:${c.port}`;
const provider=new Provider(issuer,{
  clients:[{client_id:'vault-broker',redirect_uris:[c.redirect_uri],response_types:['code'],grant_types:['authorization_code'],token_endpoint_auth_method:'none',application_type:'native',id_token_signed_response_alg:'ES256',dpop_bound_access_tokens:true}],
  jwks:{keys:[jwk]},cookies:{keys:[randomBytes(32).toString('hex')]},
  pkce:{required:()=>true,methods:['S256']},
  extraParams:['vault_grant'],
  scopes:['secret:read','secret:issue'],
  features:{devInteractions:{enabled:false},dPoP:{enabled:true,nonceSecret:randomBytes(32),requireNonce:()=>true},
    resourceIndicators:{enabled:true,getResourceServerInfo:async(_ctx,resource)=>{
      if(resource!==c.resource)throw new Error('unregistered resource');
      return {scope:'secret:read secret:issue',audience:c.resource,accessTokenFormat:'jwt',accessTokenTTL:120,jwt:{sign:{alg:'ES256'}}};
    }}},
  interactions:{url:(_ctx,interaction)=>`/test/interaction/${interaction.uid}`},
  findAccount:async(_ctx,id)=>({accountId:id,claims:async()=>({sub:id})}),
  extraTokenClaims:async()=>({nbf:Math.floor(Date.now()/1000)-1,grant_id:c.grant_id}),
});
provider.on('server_error',(_ctx,err)=>console.error('AS server error:',err.message));
const callback=provider.callback();
const server=https.createServer({key:fs.readFileSync(c.key),cert:fs.readFileSync(c.cert)},async(req,res)=>{
  try{
    if(req.url.startsWith('/test/interaction/')){
      const d=await provider.interactionDetails(req,res);
      if(d.prompt.name==='login')return await provider.interactionFinished(req,res,{login:{accountId:c.subject}},{mergeWithLastSubmission:false});
      if(d.prompt.name==='consent'){
        const grant=d.grantId?await provider.Grant.find(d.grantId):new provider.Grant({accountId:d.session.accountId,clientId:d.params.client_id});
        if(d.prompt.details.missingOIDCScope)grant.addOIDCScope(d.prompt.details.missingOIDCScope.join(' '));
        for(const [resource,scopes] of Object.entries(d.prompt.details.missingResourceScopes||{}))grant.addResourceScope(resource,scopes.join(' '));
        const grantId=await grant.save();
        return await provider.interactionFinished(req,res,{consent:{grantId}},{mergeWithLastSubmission:true});
      }
      throw new Error('unexpected interaction');
    }
    return callback(req,res);
  }catch(e){console.error('AS fixture error:',e.message);res.writeHead(500);res.end('fixture error');}
});
server.listen(c.port,'127.0.0.1',()=>fs.writeFileSync(c.ready,JSON.stringify({issuer,public_key:ECDH.convertKey(point,'prime256v1',undefined,undefined,'compressed').toString('base64url')}),{mode:0o600}));
