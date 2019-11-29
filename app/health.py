import falcon
class Health(object):
 def on_get(self, req, resp):
    resp.body = '{"explorer-api Status":"Enable"}'
    resp.status = falcon.HTTP_200
