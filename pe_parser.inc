PeParser struct

    filename 	cword      ?   ;имя файла

    fd          HANDLE  ?   ;хендл открытого файла
    mapd        HANDLE  ?   ;хендл файловой проекции
    mem	        cword   ?   ;указатель на память спроецированного файла
    filesize    cword   ?   ;размер спроецированной части файла

    doshead     cword   ?   ;указатель на DOS заголовок
    nthead      cword   ?   ;указатель на NT заголовок

    impdir      cword   ?   ;указатель на массив дескрипторов таблицы импорта
    sizeImpdir  DWORD   ?   ;размер таблицы импорта
    countImpdes DWORD   ?   ;количество элементов в таблице импорта

    expdir      cword   ?   ;указатель на таблицу экспорта
    sizeExpdir  DWORD   ?   ;размер таблицы экспорта

    sections    cword   ?   ;указатель на таблицу секций (на первый элемент)
    countSec    DWORD   ?   ;количество секций

PeParser ends


Space struct
    startRVA	DWORD	?
    endRVA		DWORD	?
    startRAW	DWORD	?
    endRAW		DWORD	?
    isize		DWORD	?
Space ends