#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>

void pwncollege();

int main(int argc, char *argv[])
{
	pwncollege();
}

void pwncollege()
{
	int status,cpid;

	// remplissage des arguments
	cpid = fork(); // création du premier enfant
	if (cpid == 0) 
	{
		execlp("/challenge/run","run",(char *) NULL); // exécution processus enfant
	}

	waitpid(-1,&status,0);
}

