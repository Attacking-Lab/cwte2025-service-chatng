import json

template_bot_calculator = {
    "init" : [
        {
            "match" : "(hey|hello|hi|good ?morning|good ?afternoon|help)",
            "actions" : [
                ["print", "Hello! How can I help you? Say `calculator` to enable my specialized mode!", False]
            ]
        },
        {
            "match" : "(goodbye|bye|see you|later)",
            "actions" : [
                ["print", "Bye!", False]
            ]
        },
        {
            "match" : "(thanks|thanx|thank ?you)",
            "actions" : [
                ["print", "No problem!", False]
            ]
        },
        {
            "match" : "calculator",
            "actions" : [
                ["print", "Calculator mode was enabled! Write `exit` to return to normal mode.", False],
                ["goto", "calc"]
            ]
        },
        {
            "match" : ".*",
            "actions" : [
                ["print", "I didn't understand... Write `help` if you want more info about how to use my abilities.", False]
            ]
        }
    ],
    "calc" : [
        {
            "match" : "(\\d+)\\s*\\+\\s*(\\d+)",
            "actions" : [
                ["print", "Let me do this addition for you... it should be ", False],
                ["add"]
            ]
        },
        {
            "match" : "(\\d+)\\s*\\-\\s*(\\d+)",
            "actions" : [
                ["print", "Let me do this subtraction for you... it should be ", False],
                ["sub"]
            ]
        },
        {
            "match" : "exit",
            "actions" : [
                ["print", "Back to normal mode", False],
                ["goto", "init"]
            ]
        }
    ]
}

def getRandomized_calculatorBot(gen):
    bot = template_bot_calculator
    bot = json.dumps(bot)
    bot.replace('"calc"', '"' + gen.genStr(gen.genInt(6,10)) + '"')
    bot.replace('I', gen.choice(['I', 'BOT', 'me']))
    bot.replace('Hello', gen.choice(['Hello', 'Hey', 'Hi']))
    bot.replace('Bye!', gen.choice(['Bye!', 'Until next time!', 'Later!', 'BB', 'CU!']))
    bot.replace('exit', gen.choice(['exit', 'terminate', 'close', 'kill']))
    return json.loads(bot)

template_bot_conversions = {
    "init" : [
        {
            "match" : "(hey|hello|hi|good ?morning|good ?afternoon|help)",
            "actions" : [
                ["print", "Hello! How can I help you? Say `conversions` to enable my specialized mode!", False]
            ]
        },
        {
            "match" : "(goodbye|bye|see you|later)",
            "actions" : [
                ["print", "Bye!", False]
            ]
        },
        {
            "match" : "(thanks|thanx|thank ?you)",
            "actions" : [
                ["print", "No problem!", False]
            ]
        },
        {
            "match" : "conversions",
            "actions" : [
                ["print", "Conversions mode was enabled! Write `exit` to return to normal mode.", False],
                ["goto", "conv"]
            ]
        },
        {
            "match" : ".*",
            "actions" : [
                ["print", "I didn't understand... Write `help` if you want more info about how to use my abilities.", False]
            ]
        }
    ],
    "conv" : [
        {
            "match" : "hex2dec\\s+([a-f0-9]+)",
            "actions" : [
                ["print", "Let me do this conversion for you... it should be ", False],
                ["hex2dec"]
            ]
        },
        {
            "match" : "dec2hex\\s+([0-9]+)",
            "actions" : [
                ["print", "Let me do this conversion for you... it should be ", False],
                ["dec2hex"]
            ]
        },
        {
            "match" : "exit",
            "actions" : [
                ["print", "Back to normal mode", False],
                ["goto", "init"]
            ]
        }
    ]
}

def getRandomized_conversionsBot(gen):
    bot = template_bot_conversions
    bot = json.dumps(bot)
    bot.replace('"conv"', '"' + gen.genStr(gen.genInt(6,10)) + '"')
    bot.replace('I', gen.choice(['I', 'BOT', 'me']))
    bot.replace('Hello', gen.choice(['Hello', 'Hey', 'Hi']))
    bot.replace('exit', gen.choice(['exit', 'terminate', 'close', 'kill']))
    return json.loads(bot)

template_bot_negative = {
    "init" : [
        {
            "match" : "(hey|hello|hi|good ?morning|good ?afternoon|help)",
            "actions" : [
                ["print", "I don't want to talk to you", False]
            ]
        },
        {
            "match" : "(goodbye|bye|see you|later)",
            "actions" : [
                ["print", "It was about time...", False]
            ]
        },
        {
            "match" : "(thanks|thanx|thank ?you)",
            "actions" : [
                ["print", "For what?", False]
            ]
        },
        {
            "match" : "(help)",
            "actions" : [
                ["print", "Indeed... you need help.", False]
            ]
        },
        {
            "match" : ".*",
            "actions" : [
                ["print", "Nonsense...", False]
            ]
        }
    ]
}

def getRandomized_negativeBot(gen):
    bot = template_bot_negative
    bot = json.dumps(bot)
    bot.replace('I', gen.choice(['I', 'BOT', 'me']))
    return json.loads(bot)

template_bot_nope = {
    "init" : [
        {
            "match" : "(a|b)",
            "actions" : [
                ["print", "Ah yes, the Fort Knox of passwords: 1234. Truly groundbreaking.", False]
            ]
        },
        {
            "match" : "(c|d)",
            "actions" : [
                ["print", "That's it? Even a CAPTCHA puts up more of a fight.", False]
            ]
        },
        {
            "match" : "(e|f)",
            "actions" : [
                ["print", "Ooo, SQL injection. So edgy. What's next, cross-site script kiddie?", False]
            ]
        },
        {
            "match" : "(g|h)",
            "actions" : [
                ["print", "Impressive… if we were still in the dial-up era.", False]
            ]
        },
        {
            "match" : "(i|j)",
            "actions" : [
                ["print", "You type like someone who learned hacking from a 10-minute YouTube tutorial.", False]
            ]
        },
        {
            "match" : "(k|l)",
            "actions" : [
                ["print", "Nice attempt. Even my error logs have more creativity.", False]
            ]
        },
        {
            "match" : "(m|n)",
            "actions" : [
                ["print", "That exploit was retired before MySpace was.", False]
            ]
        },
        {
            "match" : "(o|p)",
            "actions" : [
                ["print", "Careful, with moves like that you'll end up as a sysadmin's inside joke.", False]
            ]
        },
        {
            "match" : "(q|r)",
            "actions" : [
                ["print", "That payload's so basic, it belongs in a freshman CS class.", False]
            ]
        },
        {
            "match" : "(s|t)",
            "actions" : [
                ["print", "You call that obfuscation? My grandma's Wi-Fi password is tougher.", False]
            ]
        },
        {
            "match" : "(y|z)",
            "actions" : [
                ["print", "Bold move. Did you copy that straight from Stack Overflow?", False]
            ]
        },
        {
            "match" : ".*",
            "actions" : [
                ["print", "That script runs slower than Windows Update on a toaster.", False]
            ]
        }
    ]
}

def getRandomized_nopeBot(gen):
    bot = template_bot_nope
    bot = json.dumps(bot)
    return json.loads(bot)

def getRandomizedBot(gen):
    choice = gen.choice([1,2,3,4])
    if choice == 1:
        return getRandomized_calculatorBot(gen)
    if choice == 2:
        return getRandomized_conversionsBot(gen)
    if choice == 3:
        return getRandomized_negativeBot(gen)
    return getRandomized_nopeBot(gen)
