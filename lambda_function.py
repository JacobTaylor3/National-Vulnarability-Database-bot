import src.logic as bot

def lambda_handler(event,context):
    bot.tweet()
    
lambda_handler(2,3)

