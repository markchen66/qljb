delete __filename
delete __dirname
ActiveXObject = undefined

window = global;


content="content_code"


navigator = {"platform": "Linux aarch64"}
navigator = {"userAgent": "CtClient;11.0.0;Android;13;22081212C;NTIyMTcw!#!MTUzNzY"}

location={
    "href": "https://",
    "origin": "",
    "protocol": "",
    "host": "",
    "hostname": "",
    "port": "",
    "pathname": "",
    "search": "",
    "hash": ""
}

i = {length: 0}
base = {length: 0}
div = {
    getElementsByTagName: function (res) {
        if (res === 'i') {
            return i
        }
    return '<div></div>'
    }
}
script = {
}
meta = [
    {charset:"UTF-8"},
    {
        content: content,
        getAttribute: function (res) {
            if (res === 'r') {
                return 'm'
            }
        },
        parentNode: {
            removeChild: function (res) {
              return content
            }
        },
    }
]
form = '<form></form>'
window.addEventListener= function (res) {
    }
document = {
    createElement: function (res) {
       if (res === 'div') {
            return div
        } else if (res === 'form') {
            return form
        }
        else{return res}
    },
    addEventListener: function (res) {
    },
    appendChild: function (res) {
        return res
    },
    removeChild: function (res) {
    },
    getElementsByTagName: function (res) {
        if (res === 'script') {
            return script
        }
        if (res === 'meta') {
            return meta
        }
        if (res === 'base') {
            return base
        }
    },
    getElementById: function (res) {
        if (res === 'root-hammerhead-shadow-ui') {
            return null
        }
    }

}
window.top = window

