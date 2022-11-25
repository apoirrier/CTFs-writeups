# ASM ère

> Nous avons besoin de sécuriser des données sur un très vieux système.
>
> Heureusement, nous avons déjà de nombreux programmes très sophistiqués pour le faire.
>
> Nous avons cependant égaré l'interpreteur du langage de programmation interne à notre organisation.
>
> Veuillez programmer l'interpreteur ASMera en Python, suivant les entrées et sorties d'exemple ci-dessous.
>
> Le programme prend pour seul argument le fichier à interpreter et affiche le résultat en sortie standard.
>
> Les fonctions à gérer sont toutes présentées dans les fichiers d'exemple (il n'y a donc pas de fonction exit, pas de fonction sinon, pas de fonction compter, ...)
>
> Le test final peut contenir des opérations == != < > <= ainsi que >=

Fichiers donnés :

input.txt:
```
fonction_inutile:
message non affiché
retour

message ici un texte sans variable ni guillemets
nombre nombre_entier -10
appel fonction_simple

message test
appel messages_complexes

; un commentaire de code

affiche_nombre:
nombre nombre_exemple 0
incrementer nombre_exemple 5
; encore un commentaire
message "on affiche " $nombre_exemple " dans la console"
appel fonction_recursive
retour

messages_complexes:
message " "
message "ce message doit avoir des espaces normaux"
message "ce " "message" " " "doit" " avoir" " " "des " "espaces " "normaux aussi"
message tandis     que    ce texte,  qui    affiche   $nombre_exemple   n'aura   "que"   " des espaces"    uniques
message $nombre_exemple " peut etre affiché : " $nombre_exemple " et affiché de nouveau : " $nombre_entier " et voilà !"
message "cependant, entre des doubles guillemets, $nombre_exemple s'affiche '$nombre_exemple'"
message   "ici  on  "    "obtient "        " deux  " "espaces" "  " "entre  chaque  mot"
retour

fonction_recursive:
; troisieme commentaire
si $nombre_exemple < 10
incrementer nombre_exemple 1
incrementer nombre_entier -10
message "le nombre est " $nombre_exemple
appel fonction_recursive
finsi
retour

fonction_simple:
message bonjour
appel affiche_nombre
retour
```

output.txt:
```
ici un texte sans variable ni guillemets
bonjour
on affiche 5 dans la console
le nombre est 6
le nombre est 7
le nombre est 8
le nombre est 9
le nombre est 10
test
  
ce message doit avoir des espaces normaux
ce message doit avoir des espaces normaux aussi
tandis que ce texte, qui affiche 10 n'aura que des espaces uniques
10 peut etre affiché : 10 et affiché de nouveau : -60 et voilà !
cependant, entre des doubles guillemets, $nombre_exemple s'affiche '$nombre_exemple'
ici  on  obtient  deux  espaces  entre  chaque  mot
```

*Note: plus de fichiers ont été donnés au milieu de la compétition, mais j'ai trouvé une solution avant que ces fichiers ne soient publiés.*

## Description

Le but est de créer un interpréteur pour ce langage de programmation.

D'après l'exemple, on voit qu'il supporte un certain nombre de fonctionnalités :
- création de fonctions,
- fonction d'affichage appelée `message`,
- déclaration de variables entières,
- commentaires,
- incrémentation de variables,
- branches avec comparaisons d'entiers.

Je me suis inspiré de l'architecture x86 pour créer l'interpréteur : d'abord, je scanne le fichier dans son intégralité et construis des séries d'instructions (étape de compilation).

J'exécute ensuite le code instructions par instructions.

Ma procédure de construction est incrémentale : je cherche d'abord à avoir un flot de contrôle dans le bon ordre, puis j'implémente les fonctionnalités.

La base du fichier :

```python
import sys

def parse_code(code):
    for line in code:
        parse_line_flow(line)

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 " + sys.argv[0] + " <filename>")
        sys.exit(1)
    with open(sys.argv[1]) as f:
        code = f.read().split("\n")
    
    # Compilation time:
    parse_code(code)

    # Execution
    while execute_instruction():
        pass

if __name__ == "__main__":
    main()
```

## Compilation

Cette section présente les différentes étapes de compilation.

### Fonctions

Pour créer les fonctions, lors de l'étape de compilation, je liste toutes les instructions et les mets dans un tableau, tout en conservant des références vers le début de chaque fonction.

J'ai ainsi le flot de contrôle pour les appels de fonctions.

Dans le code ci-dessous, `instructions_main` contient les instructions de la fonction principale, `instructions_functions` les instructions de toutes les autres fonctions et `functions` est un dictionnaire qui associe le nom de chaque fonction à son adresse (position dans `instructions_functions`).

```python
# Functions
instructions_main = []
instructions_functions = []
current_function = "main"
functions = {}

def parse_line_flow(line):
    global instructions_main
    global instructions_functions
    global current_function
    global functions
    global startif

    if len(line) < 2 or line[0:2] == "; ":
        # This is a blank line or a comment
        return
    
    if " " not in line and ":" in line:
        # This is a line fonction:
        # So I add it to the list of functions
        current_function = line.split(":")[0]
        functions[current_function] = len(instructions_functions)
    elif line[:6] == "retour":
        # return instruction: I go back to main
        instructions_functions.append("retour")
        current_function = "main"
    else:
        # Parse instruction that does not concern the control flow for functions
        # So at this point, I am just adding them to the correct instruction list (if it belongs to main or not)
        instruction_stack = instructions_main if current_function == "main" else instructions_functions
        instruction_stack.append(line)
```

### Branches

Pour une instruction du type suivant :
```
(L1) si condition
.... instructions
(L2) finsi
```

Le code compilé ressemblera aux instructions suivantes :
```
adresse x: si condition est fausse alors saute à adresse y
......... instructions
adresse y: instructions après le finsi
```

J'enlève donc le `finsi` des instructions, et j'ajoute au niveau du `si condition` l'adresse du `finsi`.

Pour ce faire, j'utilise une pile temporaire `startif` qui sauvegarde l'adresse de début des `si`.
Une fois que le compilateur arrive au `finsi`, il dépile l'adresse du `si` correspondante, et ajoute au `si` l'adresse actuelle qui correspond à la prochaine instruction.

J'utilise pour ajouter l'adresse de `finsi` le symbole `###` dans l'instruction.

```python
# if statements
startif = []

# Le code suivant remplace le contenu du else dans parse_line_flow:
        instruction_stack = instructions_main if current_function == "main" else instructions_functions
        if line[:3] == "si ":
            startif.append(len(instruction_stack))
            instruction_stack.append(line)
        elif line[:5] == "finsi":
            si_instruction = startif.pop(len(startif)-1)
            instruction_stack[si_instruction] = instruction_stack[si_instruction] + f"###{len(instruction_stack)}"
        else:
            instruction_stack.append(line)
```

## Exécution du code

Pour exécuter le code, j'utilise un pointeur d'instructions de la forme `(x, i)` avec `x` qui vaut soit `main` soit `function` qui indique dans quelle liste d'instructions le programme se trouve et `i` est son indice.

La fonction `execute_instruction` met à jour ce pointeur d'instructions et effectue les actions.
Elle renvoie `True` si le programme n'est pas terminé.

### Fonctions

Pour les fonctions, on crée une pile d'adresses de retour pour savoir où retourner quand on sort d'une fonction.

Si le pointeur courant arrive sur une instruction `appel`, on ajoute l'instruction suivante sur la pile de retour, et on fait passer le pointeur courant à l'adresse de début de la fonction (qui se trouve enregistré dans le dictionnaire `functions` créé lors de la compilation).

Quand le pointeur arrive sur une instruction `retour`, on quitte la fonction: on dépile l'instruction de retour de la pile qui devient le nouveau pointeur courant.

```python
# Flow control
pointer_instruction = ("main", 0)
ret_stack = []

def execute_instruction():
    global pointer_instruction
    stack, i = pointer_instruction
    try:
        current_instruction = instructions_main[i] if stack == "main" else instructions_functions[i]
    except:
        return False
    if current_instruction[:6] == "appel ":
        ret_stack.append((stack, i+1))
        pointer_instruction = ("function", functions[current_instruction.split("appel ")[1]])
    elif current_instruction == "retour":
        pointer_instruction = ret_stack.pop(len(ret_stack)-1)
    # Code à compléter
    return True
```

### Branches

Pour les branches, quand le pointeur d'instructions arrive sur une branche `si`, il évalue la condition.

Si elle est vraie, la prochaine instruction est la suivante dans la liste, sinon on peut sauter à l'instruction notée après les symboles `###` qui a été ajoutée lors de la compilation.

```python
# Code de execute_instruction complété
elif current_instruction[:3] == "si ":
    split = current_instruction.split("si ")[1].split("###")
    finsi = int(split[-1])
    condition = "###".join(split[:len(split)-1])
    if evaluate(condition):
        pointer_instruction = (stack, i+1)
    else:
        pointer_instruction = (stack, finsi)
else:
    execute_real_instruction(current_instruction)
    pointer_instruction = (stack, i+1)
```

Les fonctions `evaluate` et `execute_real_instruction` sont implémentées ci-après.

### Variables

J'ai supposé toutes les variables globales: je crée un dictionnaire pour les variables.

Elles sont créées avec l'instruction `nombre` et incrémentées avec l'instruction `incrementer`:

```python
# Global variables
variables = {}

def execute_real_instruction(instruction):
    global variables
    if instruction[:7] == "nombre ":
        split = instruction[7:].split(" ")
        name, value = split[0], int(split[1])
        variables[name] = value
    elif instruction[:12] == "incrementer ":
        split = instruction[12:].split(" ")
        name, value = split[0], int(split[1])
        variables[name] += value
    elif instruction[:8] == "message ":
        execute_message(instruction[8:])
    else:
        print("Instruction not known")
        exit(1)
```

La fonction `execute_message` est implémentée ci-dessous.

Il y a également la fonction d'évaluation des conditions, que j'implémente grâce à `eval`:

```python
def evaluate(condition):
    split = condition.split("$") # for variables
    for i in range(1, len(split)):
        variable_name = split[i].split(" ")[0]
        split[i] = str(variables[variable_name]) + split[i][len(variable_name):]
    condition = "".join(split)
    return eval(condition)
```

### Message

La fonction qui m'a donné le plus de mal, c'était vraiment des devinettes de comprendre d'après l'exemple quand un espace était nécessaire et quand il ne l'était pas.

La logique que j'ai inférée (et qui a marchée pour avoir le flag) est la suivante :
- tout ce qui est entre guillemets est écrit tel quel;
- les variables et guillements on forcément un espace avant et après, qui n'est donc pas pris en compte;
- dans le cas où on n'est pas entre guillements, la quantité d'espaces n'importe pas et compte comme 1;
- plus quelques ajustements au cas par cas.

Ce qui donne le code suivant:

```python
def execute_message(message):
    out_message = []
    i = 0
    while i < len(message) and message[i] == ' ':
        i += 1
    if i > 0 and i < len(message) and message[i] not in '"$':
        out_message.append(' ')
    while i < len(message):
        if message[i] == '"':
            i += 1
            while i < len(message) and message[i] != '"':
                out_message.append(message[i])
                i += 1
            i += 1
            while i < len(message) and message[i] == ' ':
                i += 1
            if i < len(message) and message[i] not in '"$':
                out_message.append(' ')
        elif message[i] == '$':
            i += 1
            name = []
            while i < len(message) and message[i] != ' ':
                name.append(message[i])
                i += 1
            out_message.append(str(variables["".join(name)]))
            while i < len(message) and message[i] == ' ':
                i += 1
            if i < len(message) and message[i] not in '$"':
                out_message.append(' ')
        else:
            while i < len(message) and message[i] != ' ':
                out_message.append(message[i])
                i += 1
            while i < len(message) and message[i] == ' ':
                i += 1
            if i < len(message):
                out_message.append(' ')
    print("".join(out_message))
```

## Code final

```python
import sys

# Functions
instructions_main = []
instructions_functions = []
current_function = "main"
functions = {}

# if statements
startif = []

# Flow control
pointer_instruction = ("main", 0)
ret_stack = []

# Global variables
variables = {}

def parse_line_flow(line):
    global instructions_main
    global instructions_functions
    global current_function
    global functions
    global startif
    if len(line) < 2 or line[0:2] == "; ":
        return
    if " " not in line and ":" in line:
        current_function = line.split(":")[0]
        functions[current_function] = len(instructions_functions)
    elif line[:6] == "retour":
        instructions_functions.append("retour")
        current_function = "main"
    else:
        instruction_stack = instructions_main if current_function == "main" else instructions_functions
        if line[:3] == "si ":
            startif.append(len(instruction_stack))
            instruction_stack.append(line)
        elif line[:5] == "finsi":
            si_instruction = startif.pop(len(startif)-1)
            instruction_stack[si_instruction] = instruction_stack[si_instruction] + f"###{len(instruction_stack)}"
        else:
            instruction_stack.append(line)

def parse_code(code):
    for line in code:
        parse_line_flow(line)

def evaluate(condition):
    split = condition.split("$")
    for i in range(1, len(split)):
        variable_name = split[i].split(" ")[0]
        split[i] = str(variables[variable_name]) + split[i][len(variable_name):]
    condition = "".join(split)
    return eval(condition)

def execute_message(message):
    out_message = []
    i = 0
    while i < len(message) and message[i] == ' ':
        i += 1
    if i > 0 and i < len(message) and message[i] not in '"$':
        out_message.append(' ')
    while i < len(message):
        if message[i] == '"':
            i += 1
            while i < len(message) and message[i] != '"':
                out_message.append(message[i])
                i += 1
            i += 1
            while i < len(message) and message[i] == ' ':
                i += 1
            if i < len(message) and message[i] not in '"$':
                out_message.append(' ')
        elif message[i] == '$':
            i += 1
            name = []
            while i < len(message) and message[i] != ' ':
                name.append(message[i])
                i += 1
            out_message.append(str(variables["".join(name)]))
            while i < len(message) and message[i] == ' ':
                i += 1
            if i < len(message) and message[i] not in '$"':
                out_message.append(' ')
        else:
            while i < len(message) and message[i] != ' ':
                out_message.append(message[i])
                i += 1
            while i < len(message) and message[i] == ' ':
                i += 1
            if i < len(message):
                out_message.append(' ')
    print("".join(out_message))
        

def execute_real_instruction(instruction):
    global variables
    if instruction[:7] == "nombre ":
        split = instruction[7:].split(" ")
        name, value = split[0], int(split[1])
        variables[name] = value
    elif instruction[:12] == "incrementer ":
        split = instruction[12:].split(" ")
        name, value = split[0], int(split[1])
        variables[name] += value
    elif instruction[:8] == "message ":
        execute_message(instruction[8:])
    else:
        print("Instruction not known")
        exit(1)

def execute_instruction():
    global pointer_instruction
    stack, i = pointer_instruction
    try:
        current_instruction = instructions_main[i] if stack == "main" else instructions_functions[i]
    except:
        return False
    if current_instruction[:6] == "appel ":
        ret_stack.append((stack, i+1))
        pointer_instruction = ("function", functions[current_instruction.split("appel ")[1]])
    elif current_instruction == "retour":
        pointer_instruction = ret_stack.pop(len(ret_stack)-1)
    elif current_instruction[:3] == "si ":
        split = current_instruction.split("si ")[1].split("###")
        finsi = int(split[-1])
        condition = "###".join(split[:len(split)-1])
        if evaluate(condition):
            pointer_instruction = (stack, i+1)
        else:
            pointer_instruction = (stack, finsi)
    else:
        execute_real_instruction(current_instruction)
        pointer_instruction = (stack, i+1)
    return True

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 " + sys.argv[0] + " <filename>")
        sys.exit(1)
    with open(sys.argv[1]) as f:
        code = f.read().split("\n")
    parse_code(code)
    current_function = "main"

    while execute_instruction():
        pass

if __name__ == "__main__":
    main()
```