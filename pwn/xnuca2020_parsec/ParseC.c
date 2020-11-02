﻿#include <stdio.h>
#include <float.h>
#include <fcntl.h>
#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#define POOLSIZE  (256 * 1024)  // arbitrary size
#define SYMTABSIZE (1024*8)     // size of the symbol table stack
#define MAXNAMESIZE 32          // size of variable/function name
#define RETURNFLAG DBL_MAX             // indicate a return statement has occured in a function

/* this structure represent a symbol store in a symbol table */
typedef struct symStruct {  
    int type;                  //the type of the symbol:  Num, Char, Str, Array, Func
    char name[MAXNAMESIZE];    // record the symbol name
    double value;              // record the symbol value, or the length of string or array              
    union {
        char* funcp;            // pointer to an array or an function
        struct symStruct* list;
    } pointer;
    int levelNum;               // indicate the declare nesting level
} symbol;
symbol symtab[SYMTABSIZE];
int symPointer = 0;             // the symbol stack pointer
int currentlevel = 0;           // current nesting level

char *code_page;
char* src, * old_src;           // the text process currently

enum {
    debug, run
};
int compileState = run;          // current interpre state

double return_val = 0;           // used for reserve the return value of function

/* tokens and classes (operators last and in precedence order) */
enum {
    Num = 128, Char, Str, Array, Func,                          // variable
    Else, If, Return, While, Print, Puts, Read,                 // key word
    Assign, OR, AND, Equal, Sym, FuncSym, ArraySym, StrSym, Void,       // 
    Nequal, LessEqual, GreatEqual
};
int token;                      // current token type
union tokenValue {
    symbol* ptr;                // used when return a string or a symbol address for assignment
    double val;                 // token value, for Char or Num
} token_val;

char error_code[0x80] = {0};

/*--------------- function declaration ---------------*/
double function();
double statement();
int boolOR();
int boolAND();
int boolexp();
double expression();
double factor();
double term();
void match(int tk);
void next();
void error(char* info);
/* -------------------  lexical analysis  ---------------------------------*/
/* get the next token of the input string */
void next() {
    char* last_pos;

    while (token = *src) {
        ++src;
        if (token == '\n') {                // a new line
            if(compileState == debug)       // if on debug mode, print the currnet process line
                printf("%.*s", (int)(src - old_src), old_src);
            old_src = src;
        }
        else if (token == '/') {            // skip comments
            if (*src == '/')
                src++;
            else
                error("Cannot match '//' comments\n");
            while (*src != 0 && *src != '\n') {
                src++;
            }
        }
        else if ((token >= 'a' && token <= 'z') || (token >= 'A' && token <= 'Z') || (token == '_')) {
            last_pos = src - 1;             // process symbols
            char nameBuffer[MAXNAMESIZE];
            nameBuffer[0] = token;
            while ((*src >= 'a' && *src <= 'z') || (*src >= 'A' && *src <= 'Z') || (*src >= '0' && *src <= '9') || (*src == '_')) { 
                if (src + 1 - last_pos >= MAXNAMESIZE)
                    break;
                nameBuffer[src - last_pos] = *src;
                src++;
            }
            nameBuffer[src - last_pos] = 0;                 // get symbol name
            int i;
            for (i = symPointer-1; i >= 0; --i) {           // search symbol in symbol table 
                if (strcmp(nameBuffer, symtab[i].name) == 0) {      // if find symbol: return the token according to symbol type
                    if (symtab[i].type == Num || symtab[i].type == Char) {
                        token_val.ptr = &symtab[i];
                        token = Sym;
                    }
                    else if (symtab[i].type == FuncSym) {
                        token_val.ptr = &symtab[i];
                        token = symtab[i].type;
                    }
                    else if (symtab[i].type == ArraySym) {
                        token_val.ptr = &symtab[i];
                        token = symtab[i].type;
                    }
                    else if (symtab[i].type == Void){                        
                        token = Sym;
                        token_val.ptr = &symtab[i];
                    }
                    else if (symtab[i].type == StrSym){
                        token = StrSym;
                        token_val.ptr = &symtab[i];
                    }
                    else
                        token = symtab[i].type;
                    return;
                }
            }
            if (symPointer == SYMTABSIZE)
                error("Too many symbol defined!\n");
            strncpy(symtab[symPointer].name, nameBuffer,strlen(nameBuffer));        // if symbol not found, create a new one 

            symtab[symPointer].levelNum = currentlevel;
            symtab[symPointer].type = Void;
            token_val.ptr = &symtab[symPointer];
            symPointer++;
            token = Sym;
            return;
        }
        else if (token >= '0' && token <= '9') {        // process numbers
            token_val.val = (double)token - '0';
            while (*src >= '0' && *src <= '9') {
                token_val.val = token_val.val * 10.0 + *src++ - '0';
            }
            if (*src == '.') {
                src++;
                int countDig = 1;
                while (*src >= '0' && *src <= '9') {
                    token_val.val = token_val.val + ((double)(*src++) - '0')/(10.0 * countDig++);
                }
            }
            token = Num;
            return;
        }
        else if (token == '\'') {               // parse char 闭合问题
            token_val.val = *src++;
            token = Char;
            if (*src != '\'')
                error("wrong with char token\n");
            src++;
            return;
        }
        else if (token == '"' ) {               // parse string
            last_pos = src;
            char tval;
            unsigned int numCount = 0;
            while (*src != 0 && *src != token) {
                src++;
                numCount++;          
            }
            if (*src) {
                token_val.ptr = malloc(sizeof(char) * numCount + 8);
                if (!token_val.ptr)
                    error("Malloc error\n");
                strncpy((char*)token_val.ptr, last_pos,numCount);
                src++;
            }
            token = Str;
            return;
        }
        else if (token == '=') {            // parse '==' and '='
            if (*src == '=') {
                src++;
                token = Equal;
            }
            return;
        }
        else if (token == '!') {               // parse '!='
            if (*src == '=') {
                src++;
                token = Nequal;
            }
            return;
        }
        else if (token == '<') {               // parse '<=',  or '<'
            if (*src == '=') {
                src++;
                token = LessEqual;
            }
            return;
        }
        else if (token == '>') {                // parse '>=',  or '>'
            if (*src == '=') {
                src++;
                token = GreatEqual;
            }
            return;
        }
        else if (token == '|') {                // parse  '||'
            if (*src == '|') {
                src++;
                token = OR;
            }
            return;
        }
        else if (token == '&') {                // parse  '&&'
            if (*src == '&') {
                src++;
                token = AND;
            }
            return;
        }
        else if ( token == '*' || token == '/'  || token == ';' || token == ',' || token == '+' || token == '-' ||
            token == '(' || token == ')' || token == '{' || token == '}' ||  token == '[' || token == ']') {
            return;
        }
        else if (token == ' ' || token == '\t') {        }
        else{
            sprintf(error_code,"unexpected token: %c \n", token);
            error(error_code);
        }
    }
}

void match(int tk) {
    if (token == tk) {
        if (compileState == debug) {
            if(isprint(tk))
                printf("match: %c\n", tk );
            else
                printf("match: %d\n", tk);
        }
        next();
    }
    else {
        sprintf(error_code,"line %.*s:expected token: %c\n",(int)(src - old_src), old_src,  tk);
        error(error_code);
    }
}

/*--------------------------  grammatical analysis and run ----------------------------------*/

double term() {
    double temp = factor();
    while (token == '*' || token == '/') {
        if (token == '*') {
            match('*');
            temp *= factor();
        }
        else {
            match('/');
            temp /= factor();
        }
    }
    return temp;
}

double factor() {
    double temp = 0;
    if (token == '(') {
        match('(');
        temp = expression();
        match(')');
    }
    else if(token == Num ||  token == Char){
        temp = token_val.val;
        match(token);
    }
    else if (token == Sym) {
        temp = token_val.ptr->value;
        match(Sym);
    }
    else if (token == FuncSym) {
        return function();
    }
    else if (token == ArraySym) {
        symbol* ptr = token_val.ptr;
        match(ArraySym);
        match('[');
        int index = (int)expression();
        if (index >= 0 && index < ptr->value) {
            temp = ptr->pointer.list[index].value;
        }
        match(']');
    }
    return temp;
}

double expression() {
    double temp = term();
    while (token == '+' || token == '-') {
        if (token == '+') {
            match('+');
            temp += term();
        }
        else {
            match('-');
            temp -= term();
        }
    }
    return temp;
}

int boolexp() {
    if (token == '(') {
        match('(');
        int result = boolOR();
        match(')');
        return result;
    }
    else if (token == '!') {
        match('!');
        return boolexp();
    }
    double temp = expression();
    if (token == '>') {
        match('>');
        return temp > expression();
    }
    else if (token == '<') {
        match('<');
        return temp < expression();
    }
    else if (token == GreatEqual) {
        match(GreatEqual);
        return temp >= expression();
    }
    else if (token == LessEqual) {
        match(LessEqual);
        return temp <= expression();
    }
    else if (token == Equal) {
        match(Equal);
        return temp == expression();
    }
    return 0;
}

int boolAND() {
    int val = boolexp();           
    while (token == AND) {
        match(AND);
        if (val == 0)    return 0;         // short cut
        val = val & boolexp();
        if (val == 0) return 0;
    }
    return val;
}

int boolOR() {
    int val = boolAND();
    while (token == OR) {
        match(OR);
        if (val == 1)    return 1;         // short cut
        val = val | boolAND();
    }
    return val;
}

void skipStatments() {
    if(token == '{')
        token = *src++;
    int count = 0;
    while (token && !(token == '}' && count == 0)) {
        if (token == '}') count++;
        if (token == '{') count--;
        token = *src++;
    }
    match('}');
}

double statement() {
    if (token == '{') {
        match('{');
        while (token != '}') {
            if (RETURNFLAG == statement()) 
                return RETURNFLAG;
        }
        match('}');
    }
    else if (token == If) {
        match(If);
        match('(');
        int boolresult = boolOR();
        match(')');
        if (boolresult) {
            if (RETURNFLAG == statement()) 
                return RETURNFLAG;
        }
        else skipStatments();
        if (token == Else) {
            match(Else);
            if (!boolresult) {
                if (RETURNFLAG == statement())
                    return RETURNFLAG;
            }
            else skipStatments();
        }
    }
    else if (token == While) {
        match(While);
        char* whileStartPos = src;
        char* whileStartOldPos = old_src;
        int boolresult;
        do {
            src = whileStartPos;
            old_src = whileStartOldPos;
            token = '(';
            match('(');
            boolresult = boolOR();
            match(')');
            if (boolresult) {
                if (RETURNFLAG == statement()) 
                    return RETURNFLAG;
            }
            else skipStatments();
        }while (boolresult);
    }
    else if (token == Sym || token == ArraySym || token == StrSym) {
        symbol* s = token_val.ptr;
        int tktype = token;
        int index;
        match(tktype);
        if (tktype == ArraySym) {
            match('[');
            index = expression();
            match(']');
            match('=');
            if (index >= 0 && index < s->value) {
                s->pointer.list[index].value = expression();
            }
            else{
                printf("line %.*s: Index out of range\n",(int)(src - old_src), old_src);
                exit(-1);
            }
        }
        else {
            match('=');
            if (token == Str) {
                if (s->pointer.funcp)
                    free(s->pointer.funcp);
                s->pointer.funcp = (char*)token_val.ptr;
                s->type = StrSym;
                match(Str);
            }
            else if (token == Char) {
                s->value = token_val.val;
                s->type = Char;
                match(Char);
            }
            else if (token == StrSym){
                s->type = token_val.ptr->type;
                s->value = token_val.ptr->value;
                s->pointer = token_val.ptr->pointer;
                match(StrSym);
            }
            else{
                s->value = expression();
                s->type = Num;
            }
        }
        match(';');
    }
    else if (token == Array) {
        match(Array);
        symbol* s = token_val.ptr;
        match(Sym);
        match('(');
        int length = (int)expression();
        match(')');
        s->pointer.list = (symbol*)malloc(sizeof(struct symStruct) * length + 1);
        if (!s->pointer.list)
            error("Malloc error\n");
        for (int i = 0; i < length; ++i)
            s->pointer.list[i].type = Num;
        s->value = length;
        s->type = ArraySym;
        match(';');
    }
    else if (token == Func) {
        match(Func);
        symbol* s = token_val.ptr;
        s->type = FuncSym;
        match(Sym);
        s->pointer.funcp = src;
        s->value = token;
        skipStatments();
        match(';');
    }
    else if (token == Return) {
        match(Return);
        match('(');
        return_val = expression();
        match(')');
        match(';');
        return RETURNFLAG;
    }
    else if (token == Print || token == Read || token == Puts) {
        int func = token;
        double temp;
        match(func);
        match('(');
        char t[0x20];
        switch (func) {
        case Print: 
            temp = expression();
            printf("%lf\n", temp);
            break;
        case Puts: 
            if (token == StrSym){
                printf("%s\n", token_val.ptr->pointer.funcp);
                match(StrSym);
            }
            else{
                printf("%s\n", (char*)token_val.ptr);
                match(Str);
            }
            break;
        case Read:
            read(0,t,0x20);
            token_val.ptr->value = atof(t);
            //scanf("%lf", &token_val.ptr->value);
            token_val.ptr->type = Num;
            match(Sym);
        }
        match(')');
        match(';');
    }
    else if (token == FuncSym){
        function();
        match(';');     
    }
    return 0;
}

void error(char *info){
    write(1,info,strlen(info));
    free(code_page);
    exit(-1);
}

double function() {
    currentlevel++;
    return_val = 0;

    symbol* s = token_val.ptr;
    match(FuncSym);
    match('(');
    while (token != ')') {
        symtab[symPointer] = *token_val.ptr;
        strcpy(symtab[symPointer].name, token_val.ptr->name);
        symtab[symPointer].levelNum = currentlevel;
        symPointer++;
        match(Sym);
        if (token == ',')
            match(',');
    }
    match(')');
    char* startPos = src;
    char* startOldPos = old_src;
    int startToken = token;
    old_src = src = s->pointer.funcp;
    token = (int)s->value;
    statement();
    src = startPos;
    old_src = startOldPos;
    token = startToken;

    while (symtab[symPointer - 1].levelNum == currentlevel) {
        symPointer--;
    }
    currentlevel--;
    return return_val;
}

/*----------------------------------------------------------------*/

int main(int argc, char** argv)
{
    setbuf(stdout,0);
    setbuf(stdin,0);
    setbuf(stderr,0);
    int i, fd;
    src = "array func else if return while print puts read";
    for (i = Array; i <= Read; ++i) {
        next();
        symtab[symPointer -1].type = i;
    }
    if (!(src = old_src = code_page = (char*)malloc(POOLSIZE))) {
        printf("could not malloc(%d) for source area\n", POOLSIZE);
        return -1;
    }

    ++argv; --argc;
    if (argc > 0) {
        if (**argv == '-' && (*argv)[1] == 'd') {
            compileState = debug;
            ++argv; --argc;
        }
        else {
            compileState = run;
        }
    }
    if (argc < 1) {
        printf("usage: tryc [-d] file ...\n");
        return -1;
    }

    if ((fd = open(*argv, 0)) < 0) {                // read the source file
        printf("could not source file\n");
        return -1;
    }
    if ((i = read(fd, src, POOLSIZE - 1)) <= 0) {
        printf("read() returned %d\n", i);
        return -1;
    }
    src[i] = 0; // add EOF character
    close(fd);
    next();
    while (token != 0) {
        statement();
    }
    return 0;
}


