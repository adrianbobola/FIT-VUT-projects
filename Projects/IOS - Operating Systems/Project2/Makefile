name=proj2
cc=gcc
flags=-std=gnu99 -Wall -Wextra -Werror -pedantic
flagsout=-pthread -lrt
$(name): $(name).c
	 $(cc) $(flags) -o $(name) $(name).c $(flagsout)

clean:
	rm $(name)
	rm $(name).out

clean_output:
	rm $(name).out
	