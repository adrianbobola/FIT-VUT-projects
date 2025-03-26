#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <semaphore.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <ctype.h>
#include <stdbool.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>


#define SHARED_CREATE(ptr) { (ptr) = mmap(NULL, sizeof(*(ptr)), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0); } //macro for create shared variable
#define SHARED_DESTROY(ptr) { munmap((ptr), sizeof(ptr)); } //macro for delete shared variable

FILE *output = NULL;
int *lines_counter = NULL;
int *ne = NULL;
int *nc = NULL;
int *nb = NULL;
int *allconfirmed = NULL;
int *judgein = NULL;

sem_t *mutex = NULL;
sem_t *nojudge = NULL;
sem_t *confirmed = NULL;
sem_t *allregistred = NULL;

/* --------------------- */
int PI = 0;
int IG = 0;
int JG = 0;
int IT = 0;
int JT = 0;

/* --------------------- */

void gen_sleeptime(int range);

int space_counter(int line) { //counter spaces before text message
    if (line < 10) {
        return 7;
    } else if (line >= 10 && line < 100) {
        return 6;
    } else if (line >= 100 && line < 1000) {
        return 5;
    } else if (line >= 1000 && line < 10000) {
        return 4;
    } else {
        return 3;
    }
}

int test_par(int *input_par, int argc, char *argv[]) { //function for testing parameters from argv
    if (argc != 6) {
        fprintf(stderr, "%s", "error: number of arguments\n");
        return 1;
    }
    for (int i = 1; i < argc; i++) {
        char *string = NULL;
        int helper = (int) strtod(argv[i], &string);
        if ((strlen(string) >= 1)) {
            fprintf(stderr, "%s", "error: arguments contain character\n");
            return 1;
        }
        if ((i == 1) && (helper < 1)) {
            fprintf(stderr, "%s", "error: first argument\n");
            return 1;
        } else {
            if (helper < 0 || helper > 2000) {
                fprintf(stderr, "%s", "error: argument\n");
                return 1;
            }
        }
        input_par[i - 1] = helper;
    }
    return 0;
}

void process_judge(int jg, int jt) { //JUDGE process
    gen_sleeptime(jg);
    sem_wait(mutex);
    fprintf(output, "%d", *lines_counter);
    for (int i = 0; i < space_counter(*lines_counter); ++i) {
        fprintf(output, " ");
    }
    fprintf(output, ": JUDGE         : wants to enter\n");
    *lines_counter = *lines_counter + 1;
    sem_post(mutex);
    /* --------------------- */
    sem_wait(nojudge);
    sem_wait(mutex);
    fprintf(output, "%d", *lines_counter);
    for (int i = 0; i < space_counter(*lines_counter); ++i) {
        fprintf(output, " ");
    }

    fprintf(output, ": JUDGE         : enters                : %d     : %d     : %d\n", *ne, *nc, *nb);
    *lines_counter = *lines_counter + 1;
    *judgein = 1;
    sem_post(mutex);
    /* --------------------- */
    if (*nc < *ne) {       //waits for IMM registration
        sem_wait(mutex);
        fprintf(output, "%d", *lines_counter);
        for (int i = 0; i < space_counter(*lines_counter); ++i) {
            fprintf(output, " ");
        }
        fprintf(output, ": JUDGE         : waits for imm         : %d     : %d     : %d\n", *ne, *nc, *nb);
        *lines_counter = *lines_counter + 1;
        sem_post(mutex);
        sem_wait(allregistred);
    }   // All IMM are registred
    sem_wait(mutex);
    fprintf(output, "%d", *lines_counter);
    for (int i = 0; i < space_counter(*lines_counter); ++i) {
        fprintf(output, " ");
    }
    fprintf(output, ": JUDGE         : starts confirmation   : %d     : %d     : %d\n", *ne, *nc, *nb);
    *lines_counter = *lines_counter + 1;
    sem_post(mutex);
    gen_sleeptime(jt);
    /* --------------------- */
    sem_wait(mutex);
    *allconfirmed = *allconfirmed + *nc;
    int helper = *nc;
    *ne = 0;
    *nc = 0;
    fprintf(output, "%d", *lines_counter);
    for (int i = 0; i < space_counter(*lines_counter); ++i) {
        fprintf(output, " ");
    }
    fprintf(output, ": JUDGE         : ends confirmation     : %d     : %d     : %d\n", *ne, *nc, *nb);
    *lines_counter = *lines_counter + 1;
    for (int i = 0; i < helper; i++) {
        sem_post(confirmed);
    }
    sem_post(mutex);
    gen_sleeptime(jt);
    /* --------------------- */
    sem_wait(mutex);
    fprintf(output, "%d", *lines_counter);
    for (int i = 0; i < space_counter(*lines_counter); ++i) {
        fprintf(output, " ");
    }
    fprintf(output, ": JUDGE         : leaves                : %d     : %d     : %d\n", *ne, *nc, *nb);
    *lines_counter = *lines_counter + 1;
    *judgein = 0;
    sem_post(mutex);
    sem_post(nojudge);

    if (*allconfirmed < PI) {
        process_judge(jg, jt);
    } else {
        sem_wait(mutex);
        fprintf(output, "%d", *lines_counter);
        for (int i = 0; i < space_counter(*lines_counter); ++i) {
            fprintf(output, " ");
        }
        fprintf(output, ": JUDGE         : finishes\n");
        *lines_counter = *lines_counter + 1;
        sem_post(mutex);
    }

    exit(0);
}

void process_imigrant(int imigrant_ID, int it) { //IMMIGRANT PROCESS
    sem_wait(mutex);
    fprintf(output, "%d", *lines_counter);
    for (int i = 0; i < space_counter(*lines_counter); ++i) {
        fprintf(output, " ");
    }
    fprintf(output, ": IMM %d         : starts\n", imigrant_ID);
    *lines_counter = *lines_counter + 1;
    sem_post(mutex);
    /* --------------------- */
    sem_wait(nojudge);
    sem_wait(mutex);
    *ne = *ne + 1;
    *nb = *nb + 1;
    fprintf(output, "%d", *lines_counter);
    for (int i = 0; i < space_counter(*lines_counter); ++i) {
        fprintf(output, " ");
    }
    fprintf(output, ": IMM %d         : enters                : %d     : %d     : %d\n", imigrant_ID, *ne, *nc, *nb);
    *lines_counter = *lines_counter + 1;
    sem_post(mutex);
    sem_post(nojudge);
    /* --------------------- */
gen_sleeptime(500);
    sem_wait(mutex);
    *nc = *nc + 1;
    fprintf(output, "%d", *lines_counter);
    for (int i = 0; i < space_counter(*lines_counter); ++i) {
        fprintf(output, " ");
    }
    fprintf(output, ": IMM %d         : checks                : %d     : %d     : %d\n", imigrant_ID, *ne, *nc, *nb);
    *lines_counter = *lines_counter + 1;
    if ((*ne == *nc) && (*judgein == 1)) {
        sem_post(allregistred);
    }
    sem_post(mutex);
    /* --------------------- */
    sem_wait(confirmed);
    sem_wait(mutex);
    fprintf(output, "%d", *lines_counter);
    for (int i = 0; i < space_counter(*lines_counter); ++i) {
        fprintf(output, " ");
    }
    fprintf(output, ": IMM %d         : wants certificate     : %d     : %d     : %d\n", imigrant_ID, *ne,
            *nc, *nb);
    *lines_counter = *lines_counter + 1;
    sem_post(mutex);
    gen_sleeptime(it);
    /* --------------------- */
    sem_wait(mutex);
    fprintf(output, "%d", *lines_counter);
    for (int i = 0; i < space_counter(*lines_counter); ++i) {
        fprintf(output, " ");
    }
    fprintf(output, ": IMM %d         : got certificate       : %d     : %d     : %d\n", imigrant_ID, *ne, *nc, *nb);
    *lines_counter = *lines_counter + 1;
    sem_post(mutex);
    /* --------------------- */
    sem_wait(nojudge);
    sem_wait(mutex);
    *nb = *nb - 1;
    fprintf(output, "%d", *lines_counter);
    for (int i = 0; i < space_counter(*lines_counter); ++i) {
        fprintf(output, " ");
    }
    fprintf(output, ": IMM %d         : leaves                : %d     : %d     : %d\n", imigrant_ID, *ne, *nc, *nb);
    *lines_counter = *lines_counter + 1;
    sem_post(mutex);
    sem_post(nojudge);

    exit(0);
}

void gen_sleeptime(int range) {
    if (range != 0) {
        usleep(rand() % ((range * 1000) + 1));
    }
}

int inicialize() {
    if ((output = fopen("proj2.out", "w")) == NULL) {
        fprintf(stderr, "Error write file\n");
        return 1;
    }
    setbuf(output, NULL);

    SHARED_CREATE(lines_counter);
    SHARED_CREATE(ne);
    SHARED_CREATE(nc);
    SHARED_CREATE(nb);
    SHARED_CREATE(allconfirmed);
    SHARED_CREATE(judgein);

    *lines_counter = *lines_counter + 1;
    mutex = sem_open("/xbobol00.mutex", O_CREAT | O_EXCL, 0644, 1);
    if (mutex == SEM_FAILED) {
        return 1;
    }
    nojudge = sem_open("/xbobol00.nojudge", O_CREAT | O_EXCL, 0644, 1);
    if (nojudge == SEM_FAILED) {
        return 1;
    }
    confirmed = sem_open("/xbobol00.confirmed", O_CREAT | O_EXCL, 0644, 0);
    if (confirmed == SEM_FAILED) {
        return 1;
    }
    allregistred = sem_open("/xbobol00.allregistred", O_CREAT | O_EXCL, 0644, 0);
    if (allregistred == SEM_FAILED) {
        return 1;
    }
    return 0;

}

void clean() {
    SHARED_DESTROY(lines_counter);
    SHARED_DESTROY(ne);
    SHARED_DESTROY(nc);
    SHARED_DESTROY(nb);
    SHARED_DESTROY(allconfirmed);
    SHARED_DESTROY(judgein);
    sem_unlink("/xbobol00.mutex");
    sem_unlink("/xbobol00.nojudge");
    sem_unlink("/xbobol00.confirmed");
    sem_unlink("/xbobol00.allregistred");

    sem_close(mutex);
    sem_close(nojudge);
    sem_close(confirmed);
    sem_close(allregistred);

    if (output != NULL) {
        fclose(output);
    }
}

void gen_imigrants(int count, int delay, int it) {
    gen_sleeptime(delay);
    for (int i = 1; i <= count; i++) {
        pid_t IMG_ID = fork();
        if (IMG_ID < 0) {
            fprintf(stderr, "%s", "Fork imigrant error");
            exit(1);
        } else if (IMG_ID == 0) {
            process_imigrant(i, it);
        } else {
            gen_sleeptime(delay);
        }
    }
    exit(0);
}


int main(int argc, char **argv) {
    int input_par[5] = {0};
    if (test_par(input_par, argc, argv) != 0) {
        return 1;
    }
    PI = input_par[0];
    IG = input_par[1];
    JG = input_par[2];
    IT = input_par[3];
    JT = input_par[4];

    if (inicialize() == 1) {
        fprintf(stderr, "%s", "Semaphore create error.\n");
        clean();
        return 1;
    }

    pid_t fork_judge = fork();
    if (fork_judge < 0) {
        fprintf(stderr, "%s", "Judge FORK error\n");
        return 1;
    } else if (fork_judge == 0) {
        process_judge(JG, JT);
    } else {
        pid_t gen_imigrant = fork();
        if (gen_imigrant < 0) {
            fprintf(stderr, "%s", "Immigrant FORK error\n");
            return 1;
        } else if (gen_imigrant == 0) {
            gen_imigrants(PI, IG, IT); // gen_imigrant(count, delay, delay_cetificate)
        } else {
            int returnStatus;
            waitpid(gen_imigrant, &returnStatus, 0);
            if (returnStatus == 1) {
                return 1;
            }
        }
    }
    clean();
    return 0;
}
