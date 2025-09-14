key='abcdefghijklmnopqrstuvwxyz' 
message="hello world"
def encryption(n,message):
    result=""
    for i in message.lower():
         try:
            i=(key.inderx(i)+n)%26
            result+=key[i]
         except ValueError:
             result+=1
    return result
print