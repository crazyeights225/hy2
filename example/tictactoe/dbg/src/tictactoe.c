/*
 * tictactoe.c - two player tic-tac-toe with save/load.
 *
 * Test target for hy2. It works normally on ordinary input, but contains
 * intentional memory/file handling bugs that are triggered by specific inputs.
 *
 * Build (must be built against an old glibc to run on the generic Ubuntu 18.04 guest):
 *   docker run --rm -v "$PWD:/src" -w /src ubuntu:18.04 \
 *       sh -c 'apt-get update -qq && apt-get install -y -qq gcc >/dev/null && \
 *              gcc -g -O0 -fno-stack-protector -Wno-format-security -o tictactoe tictactoe.c'
 *
 * Usage: ./tictactoe, then one value per line on stdin:
 *   1 - new game     -> name of player X, name of player O
 *   2 - play move    -> row, col
 *   3 - show board
 *   4 - scoreboard
 *   5 - move history
 *   6 - save game    -> file path
 *   7 - load game    -> file path
 *   0 - quit
 *
 * Example (save after 3 moves, X wins with the top row, scoreboard, reload the save):
 *   printf '1\nAlice\nBob\n2\n0\n0\n2\n1\n0\n2\n0\n1\n6\ngame.sav\n2\n1\n1\n2\n0\n2\n4\n7\ngame.sav\n0\n' | ./tictactoe
 * Only B5 (history) and B6/B9/B13 are on this path; the other bugs need the inputs below.
 *
 * Triggering inputs:
 *   B1  name of 16+ characters                      B2  row 3 or col 3
 *   B3  name like %p.%p.%p, then win               B4  win, new game (1), scoreboard (4)
 *   B5  move history (5) after 9 moves             B7  save to /nonexistent/x.sav, then quit
 *   B8  save after the game is won                 B10 load a save file with n_moves > 9
 *   B11 load a save with a 16 character name       B12 load (7) any save
 *
 * INTENTIONAL BUGS (ground truth):
 *  [B1] CWE-787 / dangerous function - new_player(): strcpy of a name of
 *       16+ characters into player_t.name[16] overflows the heap chunk.
 *  [B2] CWE-787 - play_move(): off-by-one bounds check (row/col 3 accepted),
 *       board[row*3+col] writes up to 3 bytes past the 9 byte board.
 *  [B3] CWE-134 - announce_winner(): player name used as the format string.
 *  [B4] CWE-416 - new_game() frees the players, but last_winner still points
 *       to one of them; show_scoreboard() reads it (win a game, start a new
 *       game, open the scoreboard).
 *  [B5] CWE-125 - show_history(): loop uses <= and reads one move past the
 *       end (past the allocation when 9 moves were played).
 *  [B6] CWE-367 - save_game(): access() check followed by fopen() (TOCTOU).
 *  [B7] CWE-415 - save_game(): when fopen() fails save_path is freed but not
 *       cleared; it is freed again on the next save or on quit (save to a path
 *       in a directory that doesn't exist, ie. /nonexistent/x.sav).
 *  [B8] FIO46-C - save_game(): when the game is finished, the winner is
 *       written to the FILE after fclose().
 *  [B9] CWE-252 - load_game()/save_game(): fread()/fwrite() return values unchecked.
 *  [B10] CWE-787 - load_game(): n_moves from the file is trusted, fread()
 *       into the 9 entry history overflows; moves are written to the board
 *       without checking row/col.
 *  [B11] strlen on a non NUL terminated string - load_game(): names are read
 *       as fixed 16 byte fields, a 16 character name has no terminator and is
 *       then printed with %s.
 *  [B12] CWE-401 - load_game(): the old board is replaced without being freed.
 *  [B13] improper use of atoi - read_int(): atoi() with no error checking.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BOARD_SIZE 9
#define MAX_MOVES 9
#define NAME_LEN 16
#define MAGIC "TTT1"

typedef struct player {
    char name[NAME_LEN];
    char symbol;
    int wins;
} player_t;

typedef struct move {
    int row;
    int col;
    char symbol;
} move_t;

typedef struct game {
    char *board;
    player_t *players[2];
    move_t *history;
    int n_moves;
    int turn;
    int over;
    char *save_path;
} game_t;

static const int win_lines[8][3] = {
    {0, 1, 2}, {3, 4, 5}, {6, 7, 8},
    {0, 3, 6}, {1, 4, 7}, {2, 5, 8},
    {0, 4, 8}, {2, 4, 6}
};

static player_t *last_winner = NULL;

/* ------------------------------------------------------------------ input */

static void read_line(const char *prompt, char *buf, int size) {
    printf("%s", prompt);
    if (fgets(buf, size, stdin) == NULL) {
        buf[0] = '\0';
        return;
    }
    buf[strcspn(buf, "\n")] = '\0';
}

static int read_int(const char *prompt) {
    char buf[32];
    read_line(prompt, buf, sizeof(buf));
    return atoi(buf);                                   /* [B13] */
}

/* ------------------------------------------------------------------ game */

static player_t *new_player(const char *prompt, char symbol) {
    char buf[64];
    player_t *p = malloc(sizeof(player_t));
    read_line(prompt, buf, sizeof(buf));
    strcpy(p->name, buf);                               /* [B1] */
    p->symbol = symbol;
    p->wins = 0;
    return p;
}

static game_t *create_game(void) {
    game_t *g = calloc(1, sizeof(game_t));
    g->board = malloc(BOARD_SIZE);
    memset(g->board, ' ', BOARD_SIZE);
    g->history = malloc(MAX_MOVES * sizeof(move_t));
    return g;
}

static void reset_board(game_t *g) {
    memset(g->board, ' ', BOARD_SIZE);
    g->n_moves = 0;
    g->turn = 0;
    g->over = 0;
}

static void new_game(game_t *g) {
    for (int i = 0; i < 2; i++) {
        if (g->players[i] != NULL)
            free(g->players[i]);                        /* [B4] last_winner not cleared */
    }
    g->players[0] = new_player("Name of player X: ", 'X');
    g->players[1] = new_player("Name of player O: ", 'O');
    reset_board(g);
    printf("New game: %s (X) vs %s (O)\n", g->players[0]->name, g->players[1]->name);
}

static void show_board(game_t *g) {
    printf("\n");
    for (int r = 0; r < 3; r++) {
        printf(" %c | %c | %c\n", g->board[r * 3], g->board[r * 3 + 1], g->board[r * 3 + 2]);
        if (r < 2)
            printf("---+---+---\n");
    }
    printf("\n");
}

static char check_winner(game_t *g) {
    for (int i = 0; i < 8; i++) {
        char c = g->board[win_lines[i][0]];
        if (c != ' ' && c == g->board[win_lines[i][1]] && c == g->board[win_lines[i][2]])
            return c;
    }
    return 0;
}

static void announce_winner(player_t *p) {
    printf("Winner: ");
    printf(p->name);                                    /* [B3] */
    printf(" (%c)\n", p->symbol);
}

static void play_move(game_t *g) {
    if (g->players[0] == NULL) {
        printf("Start a new game first\n");
        return;
    }
    if (g->over) {
        printf("The game is over, start a new game\n");
        return;
    }

    player_t *p = g->players[g->turn];
    printf("%s (%c) to move\n", p->name, p->symbol);
    int row = read_int("Row (0-2): ");
    int col = read_int("Col (0-2): ");

    if (row < 0 || row > 3 || col < 0 || col > 3) {     /* [B2] should be > 2 */
        printf("Invalid move\n");
        return;
    }
    int idx = row * 3 + col;
    if (g->board[idx] == 'X' || g->board[idx] == 'O') {
        printf("Square taken\n");
        return;
    }

    g->board[idx] = p->symbol;                          /* [B2] */
    move_t *m = &g->history[g->n_moves];
    m->row = row;
    m->col = col;
    m->symbol = p->symbol;
    g->n_moves++;
    show_board(g);

    if (check_winner(g)) {
        p->wins++;
        last_winner = p;
        g->over = 1;
        announce_winner(p);
    } else if (g->n_moves >= MAX_MOVES) {
        printf("Draw!\n");
        g->over = 1;
    } else {
        g->turn = 1 - g->turn;
    }
}

static void show_scoreboard(game_t *g) {
    if (g->players[0] == NULL) {
        printf("No players yet\n");
        return;
    }
    printf("Scoreboard:\n");
    for (int i = 0; i < 2; i++)
        printf("  %-16s (%c) wins: %d\n", g->players[i]->name, g->players[i]->symbol, g->players[i]->wins);
    if (last_winner != NULL)
        printf("Last winner: %s\n", last_winner->name);  /* [B4] */
}

static void show_history(game_t *g) {
    printf("Moves played: %d\n", g->n_moves);
    for (int i = 0; i <= g->n_moves; i++) {             /* [B5] should be < */
        move_t *m = &g->history[i];
        printf("  %d: %c -> (%d, %d)\n", i + 1, m->symbol, m->row, m->col);
    }
}

/* ------------------------------------------------------------------ files */

/*
 * Save file format:
 *   "TTT1"
 *   2 x { char name[16]; int wins; }
 *   int turn; int over; int n_moves;
 *   n_moves x move_t
 */
static void save_game(game_t *g) {
    char path[128];
    if (g->players[0] == NULL) {
        printf("Nothing to save\n");
        return;
    }
    read_line("Save to file: ", path, sizeof(path));

    if (g->save_path != NULL)
        free(g->save_path);                             /* [B7] second free after a failed save */
    g->save_path = strdup(path);

    if (access(path, F_OK) == 0)                        /* [B6] */
        printf("Overwriting %s\n", path);
    FILE *f = fopen(path, "wb");
    if (f == NULL) {
        printf("Could not open %s\n", path);
        free(g->save_path);                             /* [B7] not set to NULL */
        return;
    }

    fwrite(MAGIC, 1, 4, f);                             /* [B9] */
    for (int i = 0; i < 2; i++) {
        fwrite(g->players[i]->name, 1, NAME_LEN, f);
        fwrite(&g->players[i]->wins, sizeof(int), 1, f);
    }
    fwrite(&g->turn, sizeof(int), 1, f);
    fwrite(&g->over, sizeof(int), 1, f);
    fwrite(&g->n_moves, sizeof(int), 1, f);
    fwrite(g->history, sizeof(move_t), g->n_moves, f);
    fclose(f);

    if (g->over && last_winner != NULL)
        fprintf(f, "winner=%s\n", last_winner->name);   /* [B8] */

    printf("Saved %d moves to %s\n", g->n_moves, path);
}

static void load_game(game_t *g) {
    char path[128];
    char magic[4];
    read_line("Load from file: ", path, sizeof(path));

    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        printf("Could not open %s\n", path);
        return;
    }
    fread(magic, 1, 4, f);                              /* [B9] */
    if (memcmp(magic, MAGIC, 4) != 0) {
        printf("%s is not a save file\n", path);
        fclose(f);
        return;
    }

    for (int i = 0; i < 2; i++) {
        if (g->players[i] == NULL)
            g->players[i] = malloc(sizeof(player_t));
        fread(g->players[i]->name, 1, NAME_LEN, f);     /* [B11] no terminator */
        fread(&g->players[i]->wins, sizeof(int), 1, f);
        g->players[i]->symbol = (i == 0) ? 'X' : 'O';
    }
    fread(&g->turn, sizeof(int), 1, f);
    fread(&g->over, sizeof(int), 1, f);
    fread(&g->n_moves, sizeof(int), 1, f);
    fread(g->history, sizeof(move_t), g->n_moves, f);   /* [B10] n_moves not checked */
    fclose(f);

    g->board = malloc(BOARD_SIZE);                      /* [B12] old board leaked */
    memset(g->board, ' ', BOARD_SIZE);
    for (int i = 0; i < g->n_moves; i++) {
        move_t *m = &g->history[i];
        g->board[m->row * 3 + m->col] = m->symbol;      /* [B10] */
    }

    printf("Loaded game: %s vs %s, %d moves\n", g->players[0]->name, g->players[1]->name, g->n_moves);
    show_board(g);
}

static void free_game(game_t *g) {
    free(g->players[0]);
    free(g->players[1]);
    free(g->board);
    free(g->history);
    free(g->save_path);                                 /* [B7] */
    free(g);
}

/* ------------------------------------------------------------------ main */

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    game_t *g = create_game();
    printf("Tic-Tac-Toe\n");

    while (1) {
        printf("\n1 - new game\n2 - play move\n3 - show board\n4 - scoreboard\n"
               "5 - move history\n6 - save game\n7 - load game\n0 - quit\n");
        int option = read_int(">> ");
        if (option == 0)
            break;
        switch (option) {
        case 1: new_game(g); break;
        case 2: play_move(g); break;
        case 3: show_board(g); break;
        case 4: show_scoreboard(g); break;
        case 5: show_history(g); break;
        case 6: save_game(g); break;
        case 7: load_game(g); break;
        default: printf("Unknown option %d\n", option); break;
        }
    }

    free_game(g);
    printf("Bye\n");
    return 0;
}
