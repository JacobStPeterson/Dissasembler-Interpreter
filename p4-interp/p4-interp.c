/*
 * CS 261 PA4: Mini-ELF interpreter
 *
 * Name: Jacob Peterson (peter2js)
 */

#include "p4-interp.h"

static char *io_buffer = NULL;

/**********************************************************************
 *                         REQUIRED FUNCTIONS
 *********************************************************************/

y86_reg_t decode_execute (y86_t *cpu, y86_inst_t inst, bool *cnd, y86_reg_t *valA)
{
    //check for null values  
    if( cnd == NULL || valA == NULL ) {
        cpu->stat = INS;
        return 0;

    }

    int64_t valE = 0;
    int64_t valB = 0;

    // switch statement deals with all individual cases for what happens in 
    //decode and execute
    switch ( inst.icode ) {

        case HALT:
            // doesn't do anything during decode
            // execute
            cpu->stat = HLT;
            // resets cpu flags
            cpu->zf = false;
            cpu->sf = false;
            cpu->of = false;
            break;
        case NOP:
            // doesnt do anything for decode or execute
            break;
        case CMOV:
            // decode
            *valA = cpu->reg[inst.ra];
            // execute
            valE = *valA;

            // all formulas are found from the textbook
            // chapter 3 page 210
            switch ( inst.ifun.cmov ) {
                case RRMOVQ:
                    *cnd = true;
                    break;
                case CMOVLE:
                    *cnd = (cpu->sf ^ cpu->of) | cpu->zf;
                    break;
                case CMOVL:
                    *cnd = cpu->sf ^ cpu->of;
                    break;
                case CMOVE:
                    *cnd = cpu->zf;
                    break;
                case CMOVNE:
                    *cnd = !cpu->zf;
                    break;
                case CMOVGE:
                    *cnd = !(cpu->sf ^ cpu->of);
                    break;
                case CMOVG:
                    *cnd = !(cpu->sf ^ cpu->of) & !cpu->zf;
                    break;
                default:
                    cpu->stat = INS;
                    break;
            }

            break;
        case IRMOVQ:
            // doesn't do anything during decode
            //execute
            valE = (uint64_t) inst.valC.v;
            break;
        case RMMOVQ:
            // decode
            *valA = cpu->reg[inst.ra];
            valB = cpu->reg[inst.rb];
            // execute
            valE = (uint64_t) valB + inst.valC.d;
            break;
        case MRMOVQ:
            // decode
            valB = cpu->reg[inst.rb];
            // execute
            // inst.d is equivalent to valC
            valE = (uint64_t) valB + inst.valC.d;
            break;
        case OPQ:
            // decode
            *valA = cpu->reg[inst.ra];
            valB = cpu->reg[inst.rb];
            // execute
            // sets the value of valE
            switch ( inst.ifun.op ) {
                case ADD:
                    valE = (int64_t)*valA + valB;
                    break;
                case SUB:
                    valE = valB - (int64_t)*valA;
                    break;
                case AND:
                    valE = (int64_t)*valA & valB;
                    break;
                case XOR:
                    valE = (int64_t)*valA ^ valB;
                    break;
                case BADOP:
                    cpu->stat = INS;
                    valE = 0;
                    break;
            }
            // sets the flags
            // every checking for a flag should have an else statement
            // as when a flag isnt true it should be set to false in the 
            // case that before this operation it was already set to true
            if ( valE == 0 ) {
                cpu->zf = true;
            } else {
                cpu->zf = false;
            } 
            
            if ( valE < 0 ) {
                cpu->sf = true;
            } else {
                cpu->sf = false;
            }
            // checks for overflow
            // first if: for addition
            // second if: for subtraction
            // first case: was it possitive overflow
            // second caser: was it negatice overflow
            if ( inst.ifun.op == 0 && ( ( (unsigned)valE < (unsigned) *valA ) 
                    || ( ( ( (signed)*valA < 0 ) == ( valB < 0 ) ) 
                    && ( ( valE < 0 ) != ( (signed)*valA < 0 ) ) ) ) ) {
                cpu->of = true;
            } else if ( inst.ifun.op == 0 ) {
                cpu->of = false;
            }

            if ( inst.ifun.op == 1 && ( ( valB > 0 && (signed)*valA < 0 
                    && valE <= 0 ) || ( valB < 0 
                    && ( (signed) *valA > 0 && valE >= 0 ) ) ) ) {
                cpu->of = true;
            } else if ( inst.ifun.op == 1 ) {
                cpu->of = false;
            }
            break;
        case JUMP:
            // doesnt do anything during decode
            // execute
            // all of these formulas come from the text book
            // chapter 3 page 190
            switch ( inst.ifun.jump ) {
                case JMP:
                    // will allows jump
                    *cnd = true;
                    break;
                case JLE:
                    *cnd = ( cpu->sf ^ cpu->of ) | cpu->zf;
                    break;
                case JL:
                    *cnd = cpu->sf ^ cpu->of;
                    break;
                case JE:
                    *cnd = cpu->zf;
                    break;
                case JNE:
                    *cnd = !cpu->zf;
                    break;
                case JGE:
                    *cnd = !( cpu->sf ^ cpu->of );
                    break;
                case JG: 
                    *cnd = !( cpu->sf ^ cpu->of ) & !cpu->zf;
                    break;
                case BADJUMP:
                    cpu->stat = INS;
                    break;
            }
            break;
        case CALL:
            // decode
            valB = cpu->reg[RSP];
            // execute
            valE = valB - 8;
            break;
        case RET:
            // decode
            *valA = cpu->reg[RSP];
            valB = cpu->reg[RSP];
            //execute
            valE = valB + 8;
            break;
        case PUSHQ:
            // decode
            *valA = cpu->reg[inst.ra];
            valB = cpu->reg[RSP];
            // execute
            valE = valB - 8;
            break;
        case POPQ:
            // decode
            *valA = cpu->reg[RSP];
            valB = cpu->reg[RSP];
            // execute
            valE = valB + 8;
            break;
        case IOTRAP:
            break;
        default: cpu->stat = INS; break;
    }

    return (y86_reg_t) valE;
}

// helper method for memory_wb_pc
bool check_valid_memory(y86_t *cpu, byte_t *memory, y86_reg_t val ) {

    if ( val > MEMSIZE || (signed) val <= 0 ) {
        cpu->stat = ADR;
        return true;
    }
    return false;
}


void memory_wb_pc (y86_t *cpu, y86_inst_t inst, byte_t *memory,
        bool cnd, y86_reg_t valA, y86_reg_t valE )
{

    y86_reg_t valM = NOREG;

    // used as a temporary pointer to a place in memory that will
    // be changed or retrieved
    uint64_t *tmp;

    switch ( inst.icode ) {

        case HALT:
            // does nothing for both memory and write back
            break;
        case NOP:
            // does nothing for both memory and write back
            break;
        case CMOV:
            // does nothing for memeory
            // write back
            if ( cnd ) { cpu->reg[inst.rb] = valE; }
            break;
        case IRMOVQ:
            // does nothing with memory
            // write back
            cpu->reg[inst.rb] = valE;
            break;
        case RMMOVQ:
            //memory
            // check to make sure the address is a valid address in memory
            if ( check_valid_memory( cpu, memory, valE ) ) {
                break;
            }
            tmp = (uint64_t*)&memory[valE];
            *tmp = valA;
            // does nothing during write back
            break;
        case MRMOVQ:
            // memory
            // check to make sure the address is a valid address in memory
            if ( check_valid_memory( cpu, memory, valE + sizeof(uint64_t) ) ) {
                break;
            }
            tmp = (uint64_t*) &memory[valE];
            valM = *tmp;
            // write back
            cpu->reg[inst.ra] = valM;
            break;
        case OPQ:
            // does nothing with memory
            // write back
            cpu->reg[inst.rb] = valE;
            break;
        case JUMP:
            // does nothing with memory and doesnt write back
            // pc
            if ( cnd ) {
                cpu->pc = (uint64_t) inst.valC.dest;
            } else {
                cpu->pc = (uint64_t) inst.valP;
            }
            break;
        case CALL:
            // memory
            if ( check_valid_memory( cpu, memory, valE ) ) {
                cpu->pc = inst.valP + 1;
                break;
            }
            tmp = (uint64_t*)&memory[valE];
            *tmp =  inst.valP;
            //write back
            cpu->reg[RSP] = valE;
            // pc
            cpu->pc = (uint64_t) inst.valC.dest;
            break;
        case RET:
            // memory
            if ( check_valid_memory( cpu, memory, valA ) ) {
                cpu->pc = inst.valP + 1;
                break;
            }
            tmp = (uint64_t*)&memory[valA];
            valM = *tmp;
            // write back
            cpu->reg[RSP] = valE;
            // pc
            cpu->pc = valM;
            break;
        case PUSHQ:
            // memory
            if ( check_valid_memory( cpu, memory, valE ) ) {
                break;
            }
            tmp = (uint64_t*)&memory[valE];
            *tmp = valA;
            // write back
            cpu->reg[RSP] =valE;
            break;
        case POPQ:
            // memory
            if ( check_valid_memory( cpu, memory, valA ) ) {
                break;
            }
            tmp = (uint64_t*)&memory[valA];
            valM = *tmp;
            // write back
            cpu->reg[RSP] = valE;
            cpu->reg[inst.ra] = valM;
            break;
        case IOTRAP:

            if ( io_buffer == NULL ) {
                io_buffer = (char *) calloc( sizeof(char), 100 );
            }
            char c;
            char* ch = &c;
            int j = 0;
            
            switch ( inst.ifun.trap ) {
                // Write a single character from memory to the output buffer.
                case CHAROUT:
                    tmp = (uint64_t *) &memory[cpu->reg[RSI]];
                    c = (char) *tmp;
                    ch[1] = '\n';
                    if ( io_buffer[0] == '\0' ) {
                        snprintf( io_buffer, 100, "%c", c );
                    } else {
                        strncat( io_buffer, ch, 100 );
                    }
                    break;
                // Read a single character from standard input into memory.
                case CHARIN:
                    tmp = (uint64_t *) &memory[cpu->reg[RDI]];
                    scanf( "%c", ch );
                    *tmp = (int) c;
                    break;
                // Write a single 64-bit integer in decimal from memory to the output buffer.
                case DECOUT:
                    
                    break;
                // Read a single 64-bit integer in decimal from standard input into memory.
                case DECIN:
                    
                    break;
                // Write a null-terminated character string from memory to the output buffer.
                case STROUT:
                    tmp = (uint64_t *) &memory[cpu->reg[RSI]];
                    c = (char) *tmp;
                    if ( io_buffer[0] == '\0' ) {
                        snprintf( io_buffer, 100, "%s", (char*) tmp );
                    } else {
                        strncat( io_buffer, (char*)tmp, 100 );
                    }
                    break;
                // Flush (copy) the output buffer to standard output and clear the buffer.
                case 5:
                    c = io_buffer[j];
                    while ( c != '\0' && c != '\n' && j < 100 ) {
                        printf( "%c", c );
                        j++;
                        c = io_buffer[j];
                    }
                    free( io_buffer );
                    io_buffer = (char *) calloc( sizeof(char), 100 );
                    break;
                default:
                    printf( "I/O Error\n" );
                    cpu->stat = HLT;
                    break;

            }
            break;
        default: cpu->stat = INS; inst.valP = cpu->pc; break;

    }

    if ( cpu->stat != AOK ) {
        free( io_buffer );
    }

    // program counter
    // only jump and call function hace conditions that will make the program
    // counter be anything other than valP
    if ( inst.icode != JUMP && inst.icode != CALL && inst.icode != RET ) {
        cpu->pc = inst.valP; 
    }

    //check if pc is exceeded memsize
    if( cpu->pc >= MEMSIZE ) {

        cpu->stat = ADR;
        cpu->pc = 0xffffffffffffffff;
    }
}

/**********************************************************************
 *                         OPTIONAL FUNCTIONS
 *********************************************************************/

void usage_p4 (char **argv)
{
    printf("Usage: %s <option(s)> mini-elf-file\n", argv[0]);
    printf(" Options are:\n");
    printf("  -h      Display usage\n");
    printf("  -H      Show the Mini-ELF header\n");
    printf("  -a      Show all with brief memory\n");
    printf("  -f      Show all with full memory\n");
    printf("  -s      Show the program headers\n");
    printf("  -m      Show the memory contents (brief)\n");
    printf("  -M      Show the memory contents (full)\n");
    printf("  -d      Disassemble code contents\n");
    printf("  -D      Disassemble data contents\n");
    printf("  -e      Execute program\n");
    printf("  -E      Execute program (trace mode)\n");
}

bool parse_command_line_p4 (int argc, char **argv,
        bool *header, bool *segments, bool *membrief, bool *memfull,
        bool *disas_code, bool *disas_data,
        bool *exec_normal, bool *exec_trace, char **filename)
{

    if ( argv == NULL ) { usage_p4( argv); return false; }

    int opt;
    bool print_help = false;

    // getopt, runs through flags that come after the program title.
    // sets certain bools to true depending of certain flags.
    while ( ( opt = getopt( argc, argv, "hHafsmMdDeE" ) ) != -1 ) {

        switch( opt ) {
	        case 'h': print_help = true; break;
	        case 'H': *header = true; break;
            case 'a': 
                *header = true; 
                *segments = true;
                *membrief = true;
                break;
            case 'f': 
                *header = true;
                *segments = true;
                *memfull = true;
                break;
            case 's': *segments = true; break;
            case 'm': *membrief = true; break;
            case 'M': *memfull = true; break;
            case 'd': *disas_code = true; break;
            case 'D': *disas_data = true; break;
            case 'e': *exec_normal = true; break;
            case 'E': 
                *exec_trace = true;
                *memfull = true;
                break;
	        default: usage_p4(argv); return false;
        }
    }

    // these are all the conditions that would make you leave the program right
    // after reading the commandline arguments
    // -m and -M cant be both in the command line
    // optind < argc - 1 prvents extra arugments
    // print_help does this action by definition
    if ( print_help || ( *membrief && *memfull ) || ( *exec_normal && *exec_trace ) 
            || optind < argc - 1 ) {

	    *header = true;
	    usage_p4(argv);
	    return false;
    }

    // get file name and check if its a file name
    *filename = argv[optind];
    if ( *filename == NULL ) { usage_p4(argv); return false; }

    return true;
}

void dump_cpu_state (y86_t cpu)
{
    printf( "Y86 CPU state:\n" );

    // prints rip and the flags info
    printf("  %crip: %016lx   flags: Z%x S%x O%x     ", '%', cpu.pc, cpu.zf, cpu.sf, cpu.of );

    switch ( cpu.stat ) {
        case AOK: printf( "AOK" ); break;
        case HLT: printf( "HLT" ); break;
        case ADR: printf( "ADR" ); break;
        case INS: printf( "INS" ); break;
    }
    printf( "\n" );

    // prints all the information inside of each register
    printf( "  %crax: %016lx    %crcx: %016lx\n", '%', cpu.reg[RAX], '%', cpu.reg[RCX] );
    printf( "  %crdx: %016lx    %crbx: %016lx\n", '%', cpu.reg[RDX], '%', cpu.reg[RBX] );
    printf( "  %crsp: %016lx    %crbp: %016lx\n", '%', cpu.reg[RSP], '%', cpu.reg[RBP] );
    printf( "  %crsi: %016lx    %crdi: %016lx\n", '%', cpu.reg[RSI], '%', cpu.reg[RDI] );
    printf( "   %cr8: %016lx     %cr9: %016lx\n", '%', cpu.reg[R8], '%', cpu.reg[R9] );
    printf( "  %cr10: %016lx    %cr11: %016lx\n", '%', cpu.reg[R10], '%', cpu.reg[R11] );
    printf( "  %cr12: %016lx    %cr13: %016lx\n", '%', cpu.reg[R12], '%', cpu.reg[R13] );
    printf( "  %cr14: %016lx\n", '%', cpu.reg[R14] );
}

