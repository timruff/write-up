#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>

void pwncollege();

int main(int argc,char *argv[])
{
    pwncollege();
}

void pwncollege()
{
    int pipefd[2], status;
    pid_t cpid;
    pipe(pipefd); // make pipe
    
    cpid=fork();  // make first child
    if(cpid==0)
    {
        dup2(pipefd[1], STDOUT_FILENO); // out frop pipe
        execlp("/challenge/run","run",(char *) NULL); // exec child
    }

    cpid=fork();  // make second child
    if(cpid==0)
    {
        close(pipefd[1]);  // close out don't use
        dup2(pipefd[1], STDOUT_FILENO); // out frop pipe
        execlp("/usr/bin/sed","sed","s/ / /",(char *) NULL); // exec child
    }
    close(pipefd[0]); // close pipes EOF run
    close(pipefd[1]); // second child don't get EOF, parent make it

    // wait child
    waitpid(-1,&status,0);
    waitpid(-1,&status,0);

}

