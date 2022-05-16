/*
 * CS 261 PA3: Mini-ELF disassembler
 *
 * Name: Jacob Peterson
 */

#include "p3-disas.h"

/**********************************************************************
 *                         REQUIRED FUNCTIONS
 *********************************************************************/


y86_inst_t fetch (y86_t *cpu, byte_t *memory)
{
    y86_inst_t ins;

    //set instruction filed to 0
   memset(&ins, 0x00, sizeof(ins));

    //check for null or out of bounds paramaters
    if(memory == NULL || cpu->pc >= MEMSIZE || cpu->pc < 0)
    {
        cpu->stat = ADR;
        ins.icode = INVALID;
        return ins;
    } 

    // instruction 
    uint8_t instr_byte = memory[cpu->pc];
    // registers
    uint8_t reg_byte;
    // destination / value
    uint64_t *dv_byte;
    // sets the ins instruction code to instr_byte since they are the same thing
    ins.icode = (instr_byte & 0xF0) >> 4;
    ins.ifun.b = (instr_byte & 0x0F);

    // decodes instructions.
    // first looks at the first byte to confirm if its halt, nop, etc
    // then once thats determined it will then check the second byte
    // which based on the y86 will make the instruction more specific or
    // invalid.
    // / 16 ensures we look at the first byte
    switch ( ins.icode ) {
        // halt
        case 0:
            if ( ins.ifun.b != 0 ) {
                // increment next line of program
                ins.icode = INVALID; 
            } 
            ins.valP = cpu->pc + 1;
            break;
        // NOP
        case 1:
            if ( ins.ifun.b != 0 ) {
                // increment next line of program
                ins.icode = INVALID;
            } 
            ins.valP = cpu->pc + 1;
            break;
        // CMOV
        case 2:
            // ensures that cmovXX is valid
            if ( ins.ifun.b >= 0 && ins.ifun.b < 7 ) {
                ins.ifun.cmov = ins.ifun.b;
                // puts the value of the registers into reg_byte
                reg_byte = memory[cpu->pc + 1];
                // puts value of registers from reg_byte into the y86 instruction
                ins.ra = (reg_byte & 0xF0) >> 4;
                ins.rb = reg_byte & 0x0F;
                // neither registers can be NOREG
                if ( ins.ra == NOREG || ins.rb == NOREG ) {
                    ins.icode = INVALID;
                }
            } else {
                ins.icode = INVALID;
                ins.ifun.cmov = BADCMOV;
            }
            ins.valP = cpu->pc + 2;
            break;
        // IRMOVQ
        case 3:
            // ensures that irmovq is valid
            if ( ins.ifun.b == 0 ) {
                // puts the value of the registers into reg_byte
                reg_byte = memory[cpu->pc + 1];
                // puts value of registers from reg_byte into the y86 instruction
                ins.rb = reg_byte & 0x0F;
                ins.ra = (reg_byte & 0xF0) >> 4;
                // store the value the preseds the registers into ins
                dv_byte = (uint64_t *) &memory[cpu->pc + 2];
                ins.valC.v = *dv_byte;
                // rb must have a register and ra cant have a register
                if ( ins.ra != NOREG || ins.rb == NOREG ) {
                    ins.icode = INVALID;
                }
            } else {
                ins.icode = INVALID;
            }
            // increment next line of program
            ins.valP = cpu->pc + 10;
            break;
        // RMMOVQ
        case 4:
            if ( ins.ifun.b == 0 ) {
                // puts the value of the registers into reg_byte
                reg_byte = memory[cpu->pc + 1];
                // puts value of registers from reg_byte into the y86 instruction
                ins.ra = (reg_byte & 0xF0) >> 4;
                ins.rb = reg_byte & 0x0F;
                // store the value the preseds the registers into ins
                dv_byte = (uint64_t *) &memory[cpu->pc + 2];
                ins.valC.d = *dv_byte;
                // ra register cant be NOREG
                if ( ins.ra == NOREG  ) {
                    ins.icode = INVALID;
                }
            } else {
                ins.icode = INVALID;
            }
            // increment next line of program
            ins.valP = cpu->pc + 10;
            break;
        // MRMOVQ
        case 5:
            if ( ins.ifun.b == 0 ) {
                // puts the value of the registers into reg_byte
                reg_byte = memory[cpu->pc + 1];
                // puts value of registers from reg_byte into the y86 instruction
                ins.ra = (reg_byte & 0xF0) >> 4;
                ins.rb = reg_byte & 0x0F;
                // store the value the preseds the registers into ins
                dv_byte = (uint64_t *) &memory[cpu->pc + 2];
                ins.valC.d = *dv_byte;
                // ra register cant be NOREG
                if ( ins.ra == NOREG  ) {
                    ins.icode = INVALID;
                }
            } else {
                ins.icode = INVALID;
            }
            // increment next line of program
            ins.valP = cpu->pc + 10;
            break;
        // OPQ
        case 6:
            // ensures that cmovXX is valid
            if ( ins.ifun.b >= 0 && ins.ifun.b < 4 ) {
                ins.ifun.op = ins.ifun.b;
                // puts the value of the registers into reg_byte
                reg_byte = memory[cpu->pc + 1];
                // puts value of registers from reg_byte into the y86 instruction
                ins.ra = (reg_byte & 0xF0) >> 4;
                ins.rb = reg_byte & 0x0F;
                // neither registers can be NOREG
                if ( ins.ra == NOREG  ) {
                    ins.icode = INVALID;
                }
            } else {
                ins.icode = INVALID;
                ins.ifun.op = BADOP;
            }
            // increment next line of program
            ins.valP = cpu->pc + 2;
            break;
        // JUMP
        case 7:
            if ( ins.ifun.b >= 0 && ins.ifun.b < 7 ) {
                ins.ifun.jump = ins.ifun.b;
                // store the value the preseds the registers into ins
                dv_byte = (uint64_t *) &memory[cpu->pc + 1];
                ins.valC.dest = *dv_byte;
            } else {
                ins.icode = INVALID;
                ins.ifun.jump = BADJUMP;
            }
            // increment next line of program
            ins.valP = cpu->pc + 9;
            break;
        // CALL
        case 8:
            if ( ins.ifun.b == 0 ) {            
                // store the value the preseds the registers into ins
                dv_byte = (uint64_t *) &memory[cpu->pc + 1];
                ins.valC.dest = *dv_byte;
            } else {
                ins.icode = INVALID;
            }
            // increment next line of program
            ins.valP = cpu->pc + 9;
            break;
        // RET
        case 9:
            if ( ins.ifun.b != 0 ) {
                ins.icode = INVALID;
            } 
            ins.valP = cpu->pc + 1;
            break;
        // PUSHQ
        case 10:
            if ( ins.ifun.b == 0 ) {
                // puts the value of the registers into reg_byte
                reg_byte = memory[cpu->pc + 1];
                // puts value of registers from reg_byte into the y86 instruction
                ins.ra = (reg_byte & 0xF0) >> 4;
                ins.rb = reg_byte & 0x0F;
                // if the register dont exist this is an invalid instruction
                if ( ins.ra == NOREG || ins.rb != NOREG ) {
                    ins.icode = INVALID;
                }
            } else {
                ins.icode = INVALID;
            }
            // increment next line of program
            ins.valP = cpu->pc + 2; 
            break;
        // POPQ
        case 11:
            if ( ins.ifun.b == 0 ) {
                // puts the value of the registers into reg_byte
                reg_byte = memory[cpu->pc + 1];
                // puts value of registers from reg_byte into the y86 instruction
                ins.ra = (reg_byte & 0xF0) >> 4;
                ins.rb = reg_byte & 0x0F; 
                // if registers dont meet this criteria then its invalid
                if ( ins.ra == NOREG || ins.rb != NOREG ) {
                    ins.icode = INVALID;
                }
            } else {
                ins.icode = INVALID;
            }
            // increment next line of program
            ins.valP = cpu->pc + 2;
            break;
        // IOTRAP
        case 12:
            // ensures that cmovXX is valid
            if ( ins.ifun.b >= 0 && ins.ifun.b < 6 ) {
                // set trap
                ins.ifun.trap = ins.ifun.b;
            } else {
                ins.icode = INVALID;
                ins.ifun.trap = BADTRAP;
            }
            // increment next line of program
            ins.valP = cpu->pc + 1;
            break;
        // any other value ( 13, 14, 15 )
        default: ins.icode = INVALID; ins.valP = cpu->pc + 1; break;  
    }

    if( ins.valP >= MEMSIZE ) { 
        cpu->stat = ADR;
        ins.icode = INVALID; 
    } 

    return ins;
}


/**********************************************************************
 *                         OPTIONAL FUNCTIONS
 *********************************************************************/


void usage_p3 (char **argv)
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
}


bool parse_command_line_p3 (int argc, char **argv,
        bool *print_header, bool *print_segments,
        bool *print_membrief, bool *print_memfull,
        bool *disas_code, bool *disas_data, char **filename)
{

    if ( argv == NULL ) { usage_p3( argv); return false; }

    int opt;
    bool print_help = false;

    // getopt, runs through flags that come after the program title.
    // sets certain bools to true depending of certain flags.
    while ( ( opt = getopt( argc, argv, "hHafsmMdD" ) ) != -1 ) {

        switch( opt ) {
	        case 'h': print_help = true; break;
	        case 'H': *print_header = true; break;
            case 'a': 
                *print_header = true; 
                *print_segments = true;
                *print_membrief = true;
                break;
            case 'f': 
                *print_header = true;
                *print_segments = true;
                *print_memfull = true;
                break;
            case 's': *print_segments = true; break;
            case 'm': *print_membrief = true; break;
            case 'M': *print_memfull = true; break;
            case 'd': *disas_code = true; break;
            case 'D': *disas_data = true; break;
	        default: usage_p3(argv); return false;
        }
    }

    // these are all the conditions that would make you leave the program right
    // after reading the commandline arguments
    // -m and -M cant be both in the command line
    // optind < argc - 1 prvents extra arugments
    // print_help does this action by definition
    if ( print_help || ( *print_membrief && *print_memfull ) || optind < argc - 1 ) {

	    *print_header = true;
	    usage_p3(argv);
	    return false;
    }

    // get file name and check if its a file name
    *filename = argv[optind];
    if ( *filename == NULL ) { usage_p3(argv); return false; }

    return true;
} // parse_command_line_p3


char* registers( y86_regnum_t registerid ) {

    char *reg;
    switch ( registerid ) {
        case 0: reg = "%rax"; break;
        case 1: reg = "%rcx"; break;
        case 2: reg = "%rdx"; break;
        case 3: reg = "%rbx"; break;
        case 4: reg = "%rsp"; break;
        case 5: reg = "%rbp"; break;
        case 6: reg = "%rsi"; break;
        case 7: reg = "%rdi"; break;
        case 8: reg = "%r8"; break;
        case 9: reg = "%r9"; break;
        case 10: reg = "%r10"; break;
        case 11: reg = "%r11"; break;
        case 12: reg = "%r12"; break;
        case 13: reg = "%r13"; break;
        case 14: reg = "%r14"; break;
        default: reg = ""; break;
    }

    return reg;
}

void disassemble (y86_inst_t inst)
{

    switch ( inst.icode ) {

        case HALT:
            printf( "halt" );
            break;
        case NOP:
            printf( "nop" );
            break;
        case CMOV:
            switch ( inst.ifun.cmov ) {
                case RRMOVQ: printf( "rrmovq" ); break;
                case CMOVLE: printf( "cmovle" ); break;
                case CMOVL: printf( "cmovl" ); break;
                case CMOVE: printf( "cmove" ); break;
                case CMOVNE: printf( "cmovne" ); break;
                case CMOVGE: printf( "cmovge" ); break;
                case CMOVG: printf( "cmovg" ); break;
                case BADCMOV: return;
            }
            printf( " %s, %s", registers( inst.ra ), registers( inst.rb ) );
            break;
        case IRMOVQ:
            printf( "irmovq 0x%lx, %s", inst.valC.v, registers( inst.rb ) );
            break;
        case RMMOVQ:
            printf( "rmmovq %s, 0x%lx", registers( inst.ra ), inst.valC.d );
            if ( inst.rb != NOREG ) { printf( "(%s)", registers( inst.rb ) ); }
            break;
        case MRMOVQ:
            printf( "mrmovq 0x%lx", inst.valC.d );
            if ( inst.rb != NOREG ) { printf( "(%s)", registers( inst.rb ) ); } 
            printf( ", %s", registers( inst.ra ) );
            break;
        case OPQ:
            switch ( inst.ifun.op ) {
                case ADD: printf( "addq" ); break;
                case SUB: printf( "subq" ); break;
                case AND: printf( "andq" ); break;
                case XOR: printf( "xorq" ); break;
                case BADOP: return;
            }
            printf( " %s, %s", registers( inst.ra ), registers( inst.rb ) );
            break;
        case JUMP:
            switch ( inst.ifun.jump ) {
                case JMP: printf( "jmp" ); break;
                case JLE: printf( "jle" ); break;
                case JL: printf( "jl" ); break;
                case JE: printf( "je" ); break;
                case JNE: printf( "jne" ); break;
                case JGE: printf( "jge" ); break;
                case JG: printf( "jg" ); break;
                case BADJUMP: return;
            }
            printf( " 0x%lx", inst.valC.dest );
            break;
        case CALL:
            printf( "call 0x%lx", inst.valC.dest );
            break;
        case RET:
            printf( "ret" );
            break;
        case PUSHQ:
            printf( "pushq %s", registers( inst.ra ) );
            break;
        case POPQ:
            printf( "popq %s", registers( inst.ra ) );
            break;
        case IOTRAP:
            printf( "iotrap " );
            switch ( inst.ifun.trap ) {
                case CHAROUT: printf( "0" ); break;
                case CHARIN: printf( "1" ); break;
                case DECOUT: printf( "2" ); break;
                case DECIN: printf( "3" ); break;
                case STROUT: printf( "4" ); break;
                case FLUSH: printf( "5" ); break;
                case BADTRAP: return;
            }
            break;
        default:
            break;
    }

}


void disassemble_code (byte_t *memory, elf_phdr_t *phdr, elf_hdr_t *hdr)
{

    y86_t cpu;			// CPU struct to store "fake" PC
    y86_inst_t ins;		// struct to hold fetched instruction

    cpu.stat = INS;
    cpu.pc = phdr->p_vaddr;
    int i = 0x100;

    // outside of loop as this should only print once
    printf( "  0x%03lx:                      | .pos 0x%03lx code\n", cpu.pc, cpu.pc );

    while ( cpu.pc < phdr->p_vaddr + phdr->p_filesz ) {

        // stage 1: fetch instruction
        ins = fetch ( &cpu, memory );

        // TODO: abort with error if instruction was invalid
        if ( ins.icode == INVALID ) { 
            //prints invalid op code
            printf("Invalid opcode: 0xf%x\n\n", ins.icode);
            return;
         }

        // the starting position is at 0x100 so only print this if thats the case
        // or in the case of NOP dont print it and increment the start by 1
        if ( ( cpu.pc == i && ins.icode != NOP ) ) {
            printf( "  0x%03lx:                      | _start:\n", cpu.pc );
        } else if ( ins.icode == NOP ) {
            i++;
        }
        // TODO: print current address and raw bytes of instruction
        printf( "  0x%03lx: ", cpu.pc );

        // print raw bytes
        unsigned char *byte_pointer = (unsigned char *) (memory + cpu.pc);
        int end = ins.valP - cpu.pc;
        for ( int i = 0; i < end; i++ ) {
            printf( "%02x", byte_pointer[i] );
        }
        // ensures the number of spaces is correct
        for ( int i = end * 2; i < 21; i++ ) {
            printf( " " );
        }
        printf( "|   " );

        // stage2: print disassembly
        disassemble ( ins );
        printf( "\n" );
        // stage 3: update PC (go to next instruction)
        cpu.pc = ins.valP;
    }
    printf( "\n" );
    return;
}


void disassemble_data (byte_t *memory, elf_phdr_t *phdr)
{
    y86_t cpu;			// CPU struct to store "fake" PC

    cpu.pc = phdr->p_vaddr;
    // outside of loop as this should only print once
    printf( "  0x%03lx:                      | .pos 0x%03lx data\n", cpu.pc, cpu.pc );
    while ( cpu.pc < phdr->p_vaddr + phdr->p_filesz ) {

        printf( "  0x%03lx: ", cpu.pc );

        // raw data from memory is stored in the data variable
        uint64_t *data = (uint64_t *) &memory[cpu.pc];
        
        // print raw bytes
        unsigned char *byte_pointer = (unsigned char *) (memory + cpu.pc);
        for ( int i = 0; i < 8; i++ ) {
            printf( "%02x", byte_pointer[i] );
        }

        printf( "     |   .quad " );

        printf( "0x%lx", *data );
        printf("\n");
        cpu.pc += 8;
    }   
    printf( "\n" );
    return; 
}


void disassemble_rodata (byte_t *memory, elf_phdr_t *phdr)
{
    bool finnished;
    int i;
    int tmp;
    uint64_t addi = phdr->p_vaddr;
    // outside of loop as this should only print once
    printf( "  0x%03lx:                      | .pos 0x%03lx rodata\n", addi, addi );

    while ( addi < phdr->p_vaddr + phdr->p_filesz ) {
        
        // boolean used to determine if more bytes need to be printed
        // ecsentially if a string has more than 10 bytes finnished will
        // later become true.
        finnished = false;
        tmp = addi;

        printf( "  0x%03lx: ", addi );

        // does the first loop through the bits ( not including the extra lines
        // that may appear if the string is has more the 8 bytes worth of info )
        for ( i = addi; i <  addi + 10; i++ ) {

            if ( memory[i] != 0x00 ) {
                printf( "%02x", memory[i] );
            } else {
                finnished = true;
                printf( "00" );
                for ( int j = i; j < addi + 9; j++ ) {
                    printf( "  " );
                }
                addi = i + 1;
                break;
            }
        }
        // increment
        if ( !finnished) { addi += 10; }

        printf( " |   .string \"" );
        
        while( memory[tmp] != 0x00 ) {
            printf( "%c", memory[tmp++] );
        }
        printf( "\"\n" );
        
        while ( !finnished ) {

            printf( "  0x%03lx: ", addi );

            for ( i = addi; i <  addi + 10; i++ ) {

                if ( memory[i] != 0x00 ) {
                    printf( "%02x", memory[i] );
                } else {
                    finnished = true;
                    printf( "00" );
                    for ( int j = i; j < addi + 9; j++ ) {
                        printf( "  " );
                    }
                    addi = i + 1;
                    printf( " | \n" );
                    break;
                }
            }
            
            if ( !finnished ) { printf( " | \n" ); addi += 10; }
        }
        
    }
    printf("\n");
    return;
}
