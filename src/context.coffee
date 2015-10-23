Valid = require('jsonschema').Validator
Validator = new Valid
assert = require 'assert'
Promise = require 'bluebird'
async = require 'async'
needle = Promise.promisifyAll(require('needle'))

schema =
    name: "sslfilter"
    type: "object"
    required: true
    additionalProperties: false
    properties:
        "SSL_CERT_INSPECTION": {"type":"boolean", "required":true}
        "SSL_DOMAIN_FILTERING": {"type":"boolean", "required":true}
        "SSL_FILTER_SCANDOMAIN_CERT": {"type":"boolean", "required":true}
        "SSL_FILTER_RESTRICT_SSL_CERT": {"type":"boolean", "required":true}
        "SSL_FILTER_WEBWARNING": {"type":"boolean", "required":true}
        "SSL_FFPROXY_DIR": {"type":"string", "required":false}
        "SSL_CONTENT_INSPECTION": {"type":"boolean", "required":true}
        "SSL_BYPASS_DATA_INSPECTION": {"type":"boolean", "required":true}
        "SSL_BYPASS_INCLUDE_DOMAIN": {"type":"boolean", "required":true}
        "SSL_INSPECT_CACHE": {"type":"boolean", "required":false}
        "SSL_INSPECT_CACHE_MAX_ENTRIES": {"type":"number", "required":false}
        "SSL_INSPECT_CACHE_PERSIST": {"type":"boolean", "required":false}
        "SSL_INSPECT_CACHE_STORE": {"type":"string", "required":false}
        "SSL_INSPECT_CABUNDLE":
            "type":"object"
            properties :
                "filename" : {"type":"string", "required":false}
                "encoding" : {"type":"string", "required":false}
                "data" : {"type":"string", "required":false}

        "SSL_INSPECT_CACERT":
            "type":"object"
            properties :
                "filename" : {"type":"string", "required":false}
                "encoding" : {"type":"string", "required":false}
                "data" : {"type":"string", "required":false}

        "SSL_INSPECT_CAKEY":
            "type":"object"
            properties :
                "filename" : {"type":"string", "required":false}
                "encoding" : {"type":"string", "required":false}
                "data" : {"type":"string", "required":false}

        "SSL_CATEGORY_POLICY":
            "type":"object"
            properties :
                "filename" : {"type":"string", "required":false}
                "encoding" : {"type":"string", "required":false}
                "data" : {"type":"string", "required":false}

        "SSL_CATEGORY_USER":
            "type":"object"
            properties :
                "filename" : {"type":"string", "required":false}
                "encoding" : {"type":"string", "required":false}
                "data" : {"type":"string", "required":false}


getPromise = ->
    return new Promise (resolve, reject) ->
        resolve()


Validate =  (config) ->
    policyConfig = {}
    if config.enable and config.coreConfig
        options = {}
        options.propertyName = 'sslfilter'
        res = Validator.validate config.coreConfig, schema, options
        if res.errors?.length
            throw new Error "sslfilter.Validate ", res


PutConfig = (baseUrl, config)->
    needle.getAsync baseUrl + "/corenova", json:true
    .then (resp) =>
        throw new Error 'invalidStatusCode' unless resp[0].statusCode is 200
        corenovas = resp[0].body
        return corenovas[0].id
    .catch (err) =>
        throw err
    .then (id) =>
        needle.putAsync baseUrl + "/corenova/#{id}/transform/include", config, json:true
        .then (resp) =>
            throw new Error 'invalidStatusCode' unless resp[0].statusCode is 200
            return { name: "sslfilter", id: id }
        .catch (err) =>
            throw err
    .then (resp) =>
        return resp
    .catch (err) =>
        throw err


Start =  (context) ->
    throw new Error 'sslfilter-storm.Start: missingParams' unless context.bInstalledPackages and context.service

    if context.instances?.length is 1
        return context
    context.instances ?= []
    configObj = context.service.factoryConfig?.config
    config = configObj[context.service.name]

    getPromise()
    .then (resp) =>
        if config.enable and config.coreConfig
            PutConfig(context.baseUrl, config.coreConfig)
            .then (resp) =>
                context.instances.push resp

        return context
    .catch (err) =>
        throw err


Update = (context) ->
    throw new Error name:'sslfilter-storm.Update: missingParams' unless context.instances and context.policyConfig

    config = context.policyConfig[context.service.name]

    getPromise()
    .then (resp) =>
        if config.enable and config.coreConfig
            PutConfig(context.baseUrl, config.coreConfig)

    .then (resp) =>
        resp

    .catch (err) =>
        throw err


Stop = (context) ->
    throw new Error name:'sslfilter-storm.Update: missingParams' unless context.instances

    getPromise()
    .then (resp) =>
        configObj = context.service.factoryConfig?.config
        config = configObj[context.service.name]

        PutConfig(context.baseUrl, config.coreConfig)

    .then (resp) =>
        return resp
    .catch (err) =>
        throw err

module.exports.Context =
    start: Start
    stop: Stop
    update: Update
    validate: Validate
