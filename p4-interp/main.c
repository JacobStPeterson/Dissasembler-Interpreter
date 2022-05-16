/*
 * CS 261: Main driver
 *
 * Name: Jacob Peterson (peter2js)
 */

#include "p1-check.h"
#include "p2-load.h"
#include "p3-disas.h"
#include "p4-interp.h"

int main (int argc, char **argv)
{
    // initializers
    bool print_h = false;
    bool print_s = false;
    bool print_mb = false;
    bool print_mf = false;
    bool print_d = false;
    bool print_D = false;
    bool print_e = false;
    bool print_E = false;

    bool *print_header = &print_h;
    bool *print_segments = &print_s;
    bool *print_membrief = &print_mb;
    bool *print_memfull = &print_mf;
    bool *disas_code = &print_d;
    bool *disas_data = &print_D;
    bool *exec_normal = &print_e;
    bool *exec_trace = &print_E;

    FILE *file;
    char *file_name;
    struct elf hdr;

    // virtual memory is a way to allocate memory for either code or data
    // that is stored in the file being read. which allows for the computer
    // to access it and use it as it is now stored inside of RAM
    byte_t *virtual_memory = calloc( sizeof( byte_t ), MEMSIZE );


    // handles command line requirements
    bool parsed = parse_command_line_p4 ( argc, argv, print_header, 
        print_segments, print_membrief, print_memfull, disas_code, disas_data, exec_normal, exec_trace, &file_name );

    // if problems in the commandline, then we must exit the system
    if ( !parsed ) { free( virtual_memory ); return EXIT_FAILURE; }


    // open file
    file = fopen( file_name, "r");

    // reads info from the file into hdr
    // exits program if the file is unable to be read
    if ( !read_header( file, &hdr ) ) {

	    printf ( "Failed to read file\n" );
        free( virtual_memory );
        return EXIT_FAILURE;
    }

    // reused code from p1
    if ( *print_header ) { dump_header( hdr ); }


    // creates an array of program headers based on the headers
    // number of program header info
    struct elf_phdr phdr[hdr.e_num_phdr];

    // reads all the program headers in phdr[]
    for ( int i = 0; i < hdr.e_num_phdr; i++ ) {

        if ( !read_phdr( file, hdr.e_phdr_start + i * 20, &phdr[i] ) ) {

            printf( "Failed to read file\n" );
            free( virtual_memory );
            return EXIT_FAILURE;
        }
    }


    // runs if -s was in the commandline
    if ( *print_segments ) { dump_phdrs ( hdr.e_num_phdr, phdr ); }


    // puts info into the virtual memory but only if the virtual memory
    // will be accessed later on
    if ( *print_memfull || *print_membrief || *disas_code || *disas_data 
        || *exec_trace || *exec_normal) {

        for ( int i = 0; i < hdr.e_num_phdr; i++ ) {
            load_segment ( file, virtual_memory, phdr[i] );
        }
    }

    // loads full virtual memory ( -M )
    // updated for project 4 to ensure that it goes after exec_trace
    if ( *print_memfull && !*exec_trace ) {

       memFull( virtual_memory );
    }

    // loads virtual memory segments pointed to by phdr's ( -m )
    if ( *print_membrief ) {

        int start;
        int end;

        // loops through the number of phdrs that are stored in virtual mem
        for ( int i = 0; i < hdr.e_num_phdr; i++ ) {

            // saves address in memory that the phdr is pointing to
            start = phdr[i].p_vaddr;
            end = start + phdr[i].p_filesz;

            // printes info about virtual memeory segment
            if ( start != end ) { dump_memory( virtual_memory, start, end ); }
        }
    }

    /////////////////////////////////////////////////////////////
    // Segment below is where new P3 Code beguns ( -d and -D ) //
    /////////////////////////////////////////////////////////////

    if ( *disas_code ) {

        printf( "Disassembly of executable contents:\n" );
        // loops through all program headers
        for ( int i = 0; i < hdr.e_num_phdr; i++ ) {

            // ensures that the program is in fact code and not data
            if ( phdr[i].p_type == CODE ) {

                disassemble_code ( virtual_memory, &( phdr[i] ), &hdr );
            }
        }
    }

    if ( *disas_data ) {

        printf( "Disassembly of data contents:\n" );

        for ( int i = 0; i < hdr.e_num_phdr; i++ ) {

            if ( phdr[i].p_type == DATA ) {

                if ( phdr[i].p_flag == 6 ) {
                    disassemble_data( virtual_memory, &( phdr[i] ) );
                } else if ( phdr[i].p_flag == 4 ) {
                    disassemble_rodata(virtual_memory, &( phdr[i] ) );
                }
            }
        }
    }

    //////////////////////////////////////////////////////////////////////
    /////////////// P4  CODE SEGMENT BELOW ( -e and -E ) /////////////////
    //////////////////////////////////////////////////////////////////////

    // initializers
    y86_t cpu;
    y86_reg_t valA = NOREG;
    y86_reg_t valE = NOREG;
    bool cond = false;
    int count = 0;

    // sets the cpu to ensure that its a clean slate
    // memset so everything is set to 0 except what comes after it
    memset( &cpu, 0x00, sizeof(cpu) );
    cpu.pc = hdr.e_entry;
    // state = AOK
    cpu.stat = 1;

    // prints all of the registers info post execution of the program
    // execute normal
    if(*exec_normal) {
        
        printf( "Beginning execution at 0x%04x\n", hdr.e_entry );
        
        //loop executes while cpu status is ok 
        do {

            cond = false;
            
            //fetch intsruction
            y86_inst_t ins = fetch( &cpu, virtual_memory );

            if ( ins.icode < 0xd || ( ins.icode == 0x2 && ins.ifun.cmov < 7) 
                    || ( ins.icode == 0x6 && ins.ifun.op < 4 ) 
                    || ( ins.icode == 0x7 && ins.ifun.jump < 7) ) {
                count++;
            }
               
            //decode and execute
            valE = decode_execute( &cpu, ins, &cond, &valA );
            
            // memory operations, write back instruction and update pc
            memory_wb_pc( &cpu, ins, virtual_memory ,cond, valA, valE );
            
            //check if pc is exceeded memsize
            if( cpu.pc >= MEMSIZE ) {

                cpu.stat = ADR;
                cpu.pc = 0xffffffffffffffff;
            }
        } while( cpu.stat == AOK );

        //print cpu status
        dump_cpu_state( cpu );
        printf( "Total execution count: %d\n", count );

    }

    // prints state of the cpu after each instruction executes
    //execute debug mode
    if( *exec_trace ) {

        printf( "Beginning execution at 0x%04lx\n", hdr.e_entry );
        dump_cpu_state( cpu );
        
        //execute while cpu status is ok
        do {

            cond = false;
            
            //fetch intsruction
            y86_inst_t ins = fetch( &cpu, virtual_memory );
            
            if ( ins.icode < 0xd || ( ins.icode == 0x2 && ins.ifun.cmov < 7) 
                    || ( ins.icode == 0x6 && ins.ifun.op < 4 ) 
                    || ( ins.icode == 0x7 && ins.ifun.jump < 7) ) {
            
                //print instruction
                printf("\nExecuting: " );  disassemble(ins); printf("\n");
                count++;
            } else {

                printf( "\nInvalid instruction at 0x%04x\n", cpu.pc );
            }

            //decode and execute
            valE = decode_execute( &cpu, ins, &cond, &valA );
            
            // memory operations, write back instruction and update pc
            memory_wb_pc( &cpu, ins, virtual_memory ,cond, valA, valE );
            

            dump_cpu_state( cpu );

        } while( cpu.stat == AOK );

        printf( "Total execution count: %d\n\n", count );
        // print memory full post exec_trace
        memFull( virtual_memory );
        
    }

    free( virtual_memory );

    return EXIT_SUCCESS;
}



void memFull( byte_t *virtual_memory ) {
    dump_memory( virtual_memory, 0, MEMSIZE );
}

