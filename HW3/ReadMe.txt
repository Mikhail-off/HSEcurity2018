Запускаем бинарник. Видим, что куда-то пропадает первый символ.
Смотрим функцию main. В ней вызывается getchar, а далее полученный
символ сравнивается с константой 30h, что является символом 0.
Если ввели символ 0, то идем в секцию, в которой видим overflow_function.
Понимаем, что это для второго задания и не вводим 0:)
Идем в другую секцию: там вызов format_string. Эта функция зовет scanf("%1020s", str),
а далее делает printf(str), что позволяет нам посмотреть стек.
Отправляем 'AAAA%x%x%x%x%x%x' или 'AAAA%<число>$x'. Замечаем, что сама строка находится
на смещении 4. 
Дальше снова смотрим код функции format_string.
----------------------------------------------------
mov     eax, ds:g_FMTVar2
cmp     eax, 0FEh
setz    al
movzx   edx, al
mov     eax, ds:g_FMTVar1
cmp     edx, eax
setnz   al
test    al, al
jz      short loc_8048B60
---------------------------------------------------
Есть такой код. Последняя строка снова прыгает на format_string.
Дальше как раз идет секция со строкой "Congratulation! You have successfully..."
Нам нужно сделать так, чтобы инструкция jz не сработала, то есть 
test    al, al
дало не 0. А не 0 она может дать, только если в переменной Var2 лежит 254, либо
в Var1 не 0. Судя по тому, что мы попадаем в цикл, скорее, всего Var1=0.

Смотрим адресса переменных Var1 и Var2. Суем их в первые 4 байта нашей строки,
говорим в фаорматной строке, что хотим записать кол-во выведенных символов
по адрессу в 4-м аргументе. Получаем 2 рабочих решения. Одно с выводом мусора,
другое лишь с одним лишним символом.

Когда записываем 254 в Var2 нужно не забыть, что сам адресс -- это уже 4 символа,
значит не хватает еще %250s. С Var1 совсем все просто.

Решения в файлах task1-A.bash и task1-B.bash







