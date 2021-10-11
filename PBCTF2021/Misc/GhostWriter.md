# Ghost Writer

> While I was writing the beginning of my new bestselling novel, a ghost possessed my keyboard and began typing in a flag! I tried to finish the story, but the computer died shortly after. Luckily, my digital voice recorder caught it all. Can you recover it?
>
> I'm a slow writer, and my custom keyboard has only 27 unique keys; "a-z" and " " (space). No other keys are used. Also, I seem to recall that there's exactly 275 key presses recorded.
>
> Note: Follows flag format, but add underscores.

Attached is a wav file.

## Description

By listening at the file, we hear someone typing on a keyboard.
We also see that each keystroke has slightly different sound, but we hope same keys have similar sounds.

## Solution

I looked at Google and found [this acoustic keylogger Git repository](https://github.com/shoyo/acoustic-keylogger).

I installed the Docker container provided, and then tinkered with it.

My solution consists of several steps:
- first I separate the keystrokes
- then I extract features from each keystroke
- then I group keystrokes that are similar, giving me a string with at most 27 different characters (letters plus space)
- I solve the monoalphabetic substitution cipher as I know the text is in English.

To use the library, I had to add some missing dependency with:
```
docker exec -it acoustic-keylogger_env_1 apt update
docker exec -it acoustic-keylogger_env_1 apt install libsndfile1-dev
```

Also, I can know the token for accessing the notebook with:
```
docker exec -it acoustic-keylogger_env_1 jupyter notebook list
```

Before tinkering, I load the file and libraries with:

```python
from acoustic_keylogger.audio_processing import *
from acoustic_keylogger.unsupervised import *
from sklearn.preprocessing import MinMaxScaler

data = wav_read("output.wav")
```

### Separating keystrokes

I want to use the `detect_keystrokes` function from the library to separate each keystroke.

What it does is simple: it first defines a threshold based on silence in the file, then browses the sound file to detect when there is sound, and separate in between.

Yet I had some issues, as the function requires to have 5 seconds of silence at the front of my file.
But instead of adding it artificially, I just removed the line `threshold          = silence_threshold(sound_data, output=output)` and put down a hardcoded value.

I have chosen the hardcoded value first by trying the method in the file, by averaging some silence time.
However this lead to too many keystrokes (I know from the challenge description that there are exactly 275 keystrokes), so I just augmented the threshold until I got the correct number.

```python
keystrokes = detect_keystrokes(data, threshold=100)
```

### Extracting features

There is a function for that. I also chose to normalize the features.

```python
X = [extract_features(x) for x in keystrokes]
X_norm = MinMaxScaler().fit_transform(X)
```

### Grouping similar keystrokes

It seemed to me that the first feature was enough to differentiate keystrokes.

To be certain, I computed the different number of values:
```python
len(set([x[0] for x in X_norm]))
```

And I got back 25.

Thus I could group similar keystrokes by assigning them a random corresponding letter:

```python
letters = {}
phrase = []
current_letter = ord('a')
for x in X_norm:
    if x[0] not in letters:
        letters[x[0]] = current_letter
        current_letter += 1
    phrase.append(letters[x[0]])
print("".join([chr(x) for x in phrase]).replace("d", " "))
```

Note that I guessed from the sound file and because it is the most occurring letter that the attributed letter `d` corresponds in reality to a space.

This is what I get: `abc efg bfe hcijk lk f hmniba klac abc ojk pnkfqqg rccqce abmljib abc mfnk plm abc pnmoa ansc nk f tccq fke abc pqfi no rhuap lrck hmfuc scubfknufq qcghlfmeo fmc qlje uqloc hmfuc fke abc hnmeo tcmc onkinki nk nao tfmsab abcmc tfo kl tfg al fkanunrfac tbfa tfo fhlja al bfrrck`

## Solving the monoalphabetic cipher

I used [dcode](https://www.dcode.fr/monoalphabetic-substitution) to solve it automatically.

This is the text I got:
```
THE DAY HAD BEGUN ON A BRIGHT NOTE THE SUN FINALLY PEELED THROUGH THE RAIN FOR THE FIRST TIME IN A WEEL AND THE FLAG IS PBCTF OPEN BRACE MECHANICAL LEYBOARDS ARE LOUD CLOSE BRACE AND THE BIRDS WERE SINGING IN ITS WARMTH THERE WAS NO WAY TO ANTICIPATE WHAT WAS ABOUT TO HAPPEN
```

Flag: `pbctf{mechanical_keyboards_are_loud}`