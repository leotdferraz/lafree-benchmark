#include "relic.h"
#include "gmp.h"
#include "paillier.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#define tmax 1 // 52 = 1 ano; 156 = 3 anos; 1560 = 30 anos
#define cmax 1 // 20 a 40 // Número de certificados válidos no mesmo período de tempo
#define iteracoes 1000        //100  //1000
#define iterdentro 100      //1000 //100

uint64_t rdtscp(){
    unsigned int lo,hi;
    __asm__ __volatile__ ("rdtscp" : "=a" (lo), "=d" (hi));
    return ((uint64_t)hi << 32) | lo;
}

static int start(){
    core_init();
    if  (core_init() != STS_OK){
        core_clean();
        return  1;
    }
    return  0;
}

int main() {

    start();

    // Declaração das variáveis
    int t = 0; // Contador de períodos de tempo
    int c = 0; // Contador de certificados válidos no mesmo período de tempo
    int b = 0; // Contador de bytes

    static uint8_t ls_pca[tmax+1][16]; for (t = 0; t < tmax+1; t++) for (b = 0; b < 16; b++) ls_pca[t][b] = 0; // 2016 linkage seeds de 128 bits (suficientes para 1 semana)
    static uint8_t ls_ra[tmax+1][16]; for (t = 0; t < tmax+1; t++) for (b = 0; b < 16; b++) ls_ra[t][b] = 0; // 2016 linkage seeds de 128 bits

    rand_bytes(ls_pca[0], 16); // Linkage Seed inicial
    rand_bytes(ls_ra[0], 16);

    uint8_t pca_id[4]; rand_bytes(pca_id, 4); // Valores de 32 bits
    uint8_t ra_id[4]; rand_bytes(ra_id, 4);

    //static uint8_t lv_dec[tmax][cmax][768]; for (t = 0; t < tmax; t++) for (c = 0; c < cmax; c++) for (b = 0; b < 768; b++) lv_dec[t][c][b] = 0;

    uint8_t ent_hash[20]; for (b = 0; b < 20; b++) ent_hash[b] = 0;
    uint8_t sai_hash[32]; for (b = 0; b < 32; b++) sai_hash[b] = 0;

    uint8_t ent_aes[6]; for (b = 0; b < 6; b++) ent_aes[b] = 0;
    uint8_t sai_aes[32]; for (b = 0; b < 32; b++) sai_aes[b] = 0;
    uint8_t vi_aespca[16];
    uint8_t vi_aesra[16];
    int tam_saida = 0;
    int it = 0;
    int it2 = 0;

    // Tempo Ciclos

    uint64_t tigen = 0;
    uint64_t tfgen = 0;
    double ttgen = 0;
    double medgen = 0;
    uint64_t vgen[iteracoes]; for (it = 0; it < iteracoes; it++) vgen[it] = 0;
    double vargen = 0;
    double desviogen = 0;

    uint64_t tiencpca = 0;
    uint64_t tfencpca = 0;
    double ttencpca = 0;
    double medencpca = 0;
    uint64_t vencpca[iteracoes]; for (it = 0; it < iteracoes; it++) vencpca[it] = 0;
    double varencpca = 0;
    double desvioencpca = 0;

    uint64_t tiencra = 0;
    uint64_t tfencra = 0;
    double ttencra = 0;
    double medencra = 0;
    uint64_t vencra[iteracoes]; for (it = 0; it < iteracoes; it++) vencra[it] = 0;
    double varencra = 0;
    double desvioencra = 0;

    uint64_t tidec = 0;
    uint64_t tfdec = 0;
    double ttdec = 0;
    double meddec = 0;
    uint64_t vdec[iteracoes]; for (it = 0; it < iteracoes; it++) vdec[it] = 0;
    double vardec = 0;
    double desviodec = 0;

    uint64_t tiadd = 0;
    uint64_t tfadd = 0;
    double ttadd = 0;
    double medadd = 0;
    uint64_t vadd[iteracoes]; for (it = 0; it < iteracoes; it++) vadd[it] = 0;
    double varadd = 0;
    double desvioadd = 0;

    // Tempo segundos

    double ttgens = 0;
    double medgens = 0;
    ull_t vgens[iteracoes]; for (it = 0; it < iteracoes; it++) vgens[it] = 0;
    double vargens = 0;
    double desviogens = 0;

    double ttencpcas = 0;
    double medencpcas = 0;
    ull_t vencpcas[iteracoes]; for (it = 0; it < iteracoes; it++) vencpcas[it] = 0;
    double varencpcas = 0;
    double desvioencpcas = 0;

    double ttencras = 0;
    double medencras = 0;
    ull_t vencras[iteracoes]; for (it = 0; it < iteracoes; it++) vencras[it] = 0;
    double varencras = 0;
    double desvioencras = 0;

    double ttdecs = 0;
    double meddecs = 0;
    ull_t vdecs[iteracoes]; for (it = 0; it < iteracoes; it++) vdecs[it] = 0;
    double vardecs = 0;
    double desviodecs = 0;

    double ttadds = 0;
    double medadds = 0;
    ull_t vadds[iteracoes]; for (it = 0; it < iteracoes; it++) vadds[it] = 0;
    double varadds = 0;
    double desvioadds = 0;

    paillier_pubkey_t *pub;
    paillier_prvkey_t *prv;
    paillier_plaintext_t *pt1;
    paillier_ciphertext_t *ct1;
    paillier_plaintext_t *pt2;
    paillier_ciphertext_t *ct2;
    paillier_plaintext_t *lvd;
    paillier_ciphertext_t *lve;
    uint8_t *lvdec;

    FILE *out_file;
    out_file = fopen("saida.txt", "wb");
    fprintf(out_file, "tmax = %d\ncmax = %d\niteracoes = %d\n\n", tmax, cmax, iteracoes);

    // Fim declaração

    for (it = 0; it < iteracoes; it++){
        //Init Medias
        medgen = 0;
        medgens = 0;
        medencpca = 0;
        medencpcas = 0;
        medencra = 0;
        medencras = 0;
        meddec = 0;
        meddecs = 0;
        medadd = 0;
        medadds = 0;

        for (it2 = 0; it2 < iterdentro; it2++){
            printf("it = %d, itd = %d\n", it, it2);

            // Init
            rand_bytes(vi_aespca, 16); // VI do AES-128
            rand_bytes(vi_aesra, 16); // VI do AES-128
            pt1 = paillier_plaintext_from_ui(0);
            ct1 = paillier_create_enc_zero();
            pt2 = paillier_plaintext_from_ui(0);
            ct2 = paillier_create_enc_zero();
            lvd = paillier_plaintext_from_ui(0);
            lve = paillier_create_enc_zero();


            // Início Bench Gen
            bench_reset();
            bench_before();
            tigen = rdtscp();

            // PCA

            // Geração de chaves Paillier	
            paillier_keygen(3072, &pub, &prv, paillier_get_rand_devurandom);

            // Fim Bench Gen
            tfgen = rdtscp();
            medgen += tfgen - tigen;
            bench_after();
            bench_compute(1);
            medgens += bench_total();


            // Início Bench Enc PCA
            bench_reset();
            bench_before();
            tiencpca = rdtscp();

            // Armazena entrada do ID da PCA na entrada do hash
            memcpy(ent_hash, pca_id, 4);

            // Para cada período de tempo
            for (t = 0; t < tmax; t++){
                // Cálculo das Linkage Seeds usando SHA-256

                // Armazena a Linkage Seed anterior na entrada do hash concatenando com o ID da PCA
                memcpy(ent_hash+4, ls_pca[t], 16);

                // SHA-256
                md_map_sh256(sai_hash, ent_hash, 20);

                // Armazena os 16 primeiros bytes de saída do hash
                memcpy(ls_pca[t+1], sai_hash, 16);

                // Cálculo PLV usando AES-128

                // Armazena o ID da PCA na entrada do AES-128
                memcpy(ent_aes, pca_id, 4);

                // Para cada certificado válido em um mesmo período de tempo
                for(c = 0; c < cmax; c++){

                    // Concatena o valor de c na entrada do AES-128
                    ent_aes[4] = c;

                    tam_saida = 32;

                    // Encriptação AES-128
                    bc_aes_cbc_enc(sai_aes, &tam_saida, ent_aes, 6, ls_pca[t+1], 128, vi_aespca);

                    //printf("plv_pca[%d][%d] = ", t, c); for (b = 0; b < 8; b++) printf("%02X", sai_aes[b]); printf("\n");

                    tam_saida = 768;

                    // Encriptação Paillier
                    pt1 = paillier_plaintext_from_bytes(sai_aes, 8);
                    paillier_enc(ct1, pub, pt1, paillier_get_rand_devurandom);
                }
            }
            // Fim Bench Enc PCA
            tfencpca = rdtscp();
            medencpca += tfencpca - tiencpca;
            bench_after();
            bench_compute(1);
            medencpcas += bench_total();

            //printf("enc pca ok\n");

            // RA

            // Inicio Bench Enc RA
            bench_reset();
            bench_before();
            tiencra = rdtscp();

            // Armazena entrada do ID da RA na entrada do hash
            memcpy(ent_hash, ra_id, 4);

            // Para cada período de tempo
            for (t = 0; t < tmax; t++){
                // Cálculo das Linkage Seeds usando SHA-256

                // Armazena a Linkage Seed anterior na entrada do hash concatenando com o ID da RA
                memcpy(ent_hash+4, ls_ra[t], 16);

                // SHA-256
                md_map_sh256(sai_hash, ent_hash, 20);

                // Armazena os 16 primeiros bytes de saída do hash
                memcpy(ls_ra[t+1], sai_hash, 16);

                // Cálculo PLV usando AES-128

                // Armazena o ID da RA na entrada do AES-128
                memcpy(ent_aes, ra_id, 4);

                // Para cada certificado válido em um mesmo período de tempo
                for(c = 0; c < cmax; c++){
                    // Concatena o valor de c na entrada do AES-128
                    ent_aes[4] = c;

                    tam_saida = 32;

                    // Encriptação AES-128
                    bc_aes_cbc_enc(sai_aes, &tam_saida, ent_aes, 6, ls_ra[t+1], 128, vi_aesra);

                    //printf("plv_ra[%d][%d] = ", t, c); for (b = 0; b < 8; b++) printf("%02X", sai_aes[b]); printf("\n");

                    tam_saida = 768;

                    // Encriptação Paillier
					
                    pt2 = paillier_plaintext_from_bytes(sai_aes, 8);
                    paillier_enc(ct2, pub, pt2, paillier_get_rand_devurandom);
                }
            }

            // Fim Bench Enc RA
            tfencra = rdtscp();
            medencra += tfencra - tiencra;
            bench_after();
            bench_compute(1);
            medencras += bench_total();

            // Inicio Bench Soma
            bench_reset();
            bench_before();
            tiadd = rdtscp();

            for (t = 0; t < tmax; t++){
                for(c = 0; c < cmax; c++){

                    // Cálculo dos Linkage Values

                    paillier_mul(pub, lve, ct1, ct2);
                }
            }

            // Fim Bench Soma
            tfadd = rdtscp();
            medadd += tfadd - tiadd;
            bench_after();
            bench_compute(1);
            medadds += bench_total();

            // Dec (PCA)

            // Início Bench Dec
            bench_reset();
            bench_before();
            tidec = rdtscp();

            for (t = 0; t < tmax; t++){
                for(c = 0; c < cmax; c++){
					
                    paillier_dec(lvd, pub, prv, lve);
                    lvdec = (uint8_t*) paillier_plaintext_to_bytes(9, lvd);

                    //printf("lv_dec[%d][%d] = ", t, c); for(b = 0; b < 9; b++) printf("%02X", lvdec[b]); printf("\n");

                }
            }

            // Fim Bench Dec
            tfdec = rdtscp();
            meddec += tfdec - tidec;
            bench_after();
            bench_compute(1);
            meddecs += bench_total();

        }// fim loop it2

        // Medias
        medgen /= (double)iterdentro;
        medgens /= (double)iterdentro;
        vgens[it] = medgens;
        ttgens += vgens[it];
        vgen[it] = medgen;
        ttgen += vgen[it];

        medencpca /= (double)iterdentro;
        medencpcas /= (double)iterdentro;
        vencpcas[it] = medencpcas;
        ttencpcas += vencpcas[it];
        vencpca[it] = medencpca;
        ttencpca += vencpca[it];

        medencra /= (double)iterdentro;
        medencras /= (double)iterdentro;
        vencras[it] = medencras;
        ttencras += vencras[it];
        vencra[it] = medencra;
        ttencra += vencra[it];

        medadd /= (double)iterdentro;
        medadds /= (double)iterdentro;
        vadds[it] = medadds;
        ttadds += vadds[it];
        vadd[it] = medadd;
        ttadd += vadd[it];

        meddec /= (double)iterdentro;
        meddecs /= (double)iterdentro;
        vdecs[it] = meddecs;
        ttdecs += vdecs[it];
        vdec[it] = meddec;
        ttdec += vdec[it];

        // Print
        fprintf(out_file,"it = %d\n", it);
        fprintf(out_file, "Tempo Gen (Cyc)     = %lu ", vgen[it]);    fprintf(out_file, "Tempo Gen (NSec)     = %llu\n", vgens[it]);
        fprintf(out_file, "Tempo Enc PCA (Cyc) = %lu ", vencpca[it]); fprintf(out_file, "Tempo Enc PCA (NSec) = %llu\n", vencpcas[it]);
        fprintf(out_file, "Tempo Enc RA (Cyc)  = %lu ", vencra[it]);  fprintf(out_file, "Tempo Enc RA (NSec)  = %llu\n", vencras[it]);
        fprintf(out_file, "Tempo Soma (Cyc)    = %lu ", vadd[it]);    fprintf(out_file, "Tempo Soma (NSec)    = %llu\n", vadds[it]);
        fprintf(out_file, "Tempo Dec (Cyc)     = %lu ", vdec[it]);    fprintf(out_file, "Tempo Dec (NSec)     = %llu\n", vdecs[it]);
    }// fim loop it

    ttgen /= (double)iteracoes;
    ttencpca /= (double)iteracoes;
    ttencra /= (double)iteracoes;
    ttadd /= (double)iteracoes;
    ttdec /= (double)iteracoes;

    ttgens /= (double)iteracoes;
    ttencpcas /= (double)iteracoes;
    ttencras /= (double)iteracoes;
    ttadds /= (double)iteracoes;
    ttdecs /= (double)iteracoes;

    fprintf(out_file, "\nCiclos\n");
    fprintf(out_file, "Media Gen     = %lf\n", ttgen);
    fprintf(out_file, "Media Enc PCA = %lf\n", ttencpca);
    fprintf(out_file, "Media Enc RA  = %lf\n", ttencra);
    fprintf(out_file, "Media Add     = %lf\n", ttadd);
    fprintf(out_file, "Media Dec     = %lf\n", ttdec);

    fprintf(out_file, "\nNano Segundos\n");
    fprintf(out_file, "Media Gen     = %lf\n", ttgens);
    fprintf(out_file, "Media Enc PCA = %lf\n", ttencpcas);
    fprintf(out_file, "Media Enc RA  = %lf\n", ttencras);
    fprintf(out_file, "Media Add     = %lf\n", ttadds);
    fprintf(out_file, "Media Dec     = %lf\n", ttdecs);

    for (it = 0; it < iteracoes; it++){
        vargen += (vgen[it] - ttgen)*(vgen[it] - ttgen);
        varencpca += (vencpca[it] - ttencpca)*(vencpca[it] - ttencpca);
        varencra += (vencra[it] - ttencra)*(vencra[it] - ttencra);
        varadd += (vadd[it] - ttadd)*(vadd[it] - ttadd);
        vardec += (vdec[it] - ttdec)*(vdec[it] - ttdec);

        vargens += (vgens[it] - ttgens)*(vgens[it] - ttgens);
        varencpcas += (vencpcas[it] - ttencpcas)*(vencpcas[it] - ttencpcas);
        varencras += (vencras[it] - ttencras)*(vencras[it] - ttencras);
        varadds += (vadds[it] - ttadds)*(vadds[it] - ttadds);
        vardecs += (vdecs[it] - ttdecs)*(vdecs[it] - ttdecs);
    }

    vargen /= (double)iteracoes;
    varencpca /= (double)iteracoes;
    varencra /= (double)iteracoes;
    varadd /= (double)iteracoes;
    vardec /= (double)iteracoes;

    vargens /= (double)iteracoes;
    varencpcas /= (double)iteracoes;
    varencras /= (double)iteracoes;
    varadds /= (double)iteracoes;
    vardecs /= (double)iteracoes;

    desviogen = sqrt(vargen);
    desvioencpca = sqrt(varencpca);
    desvioencra = sqrt(varencra);
    desvioadd = sqrt(varadd);
    desviodec = sqrt(vardec);

    desviogens = sqrt(vargens);
    desvioencpcas = sqrt(varencpcas);
    desvioencras = sqrt(varencras);
    desvioadds = sqrt(varadds);
    desviodecs = sqrt(vardecs);

    fprintf(out_file, "\nCiclos\n");
    fprintf(out_file, "Desvio Padrao Gen     = %lf\n", desviogen);
    fprintf(out_file, "Desvio Padrao Enc PCA = %lf\n", desvioencpca);
    fprintf(out_file, "Desvio Padrao Enc RA  = %lf\n", desvioencra);
    fprintf(out_file, "Desvio Padrao Soma    = %lf\n", desvioadd);
    fprintf(out_file, "Desvio Padrao Dec     = %lf\n", desviodec);

    fprintf(out_file, "\nNano Segundos\n");
    fprintf(out_file, "Desvio Padrao Gen     = %lf\n", desviogens);
    fprintf(out_file, "Desvio Padrao Enc PCA = %lf\n", desvioencpcas);
    fprintf(out_file, "Desvio Padrao Enc RA  = %lf\n", desvioencras);
    fprintf(out_file, "Desvio Padrao Soma    = %lf\n", desvioadds);
    fprintf(out_file, "Desvio Padrao Dec     = %lf", desviodecs);

    fflush(out_file);
    fclose(out_file);

    printf("ok\n");

    paillier_freepubkey(pub);
    paillier_freeprvkey(prv);
    paillier_freeplaintext(pt1);
    paillier_freeciphertext(ct1);
    paillier_freeplaintext(pt2);
    paillier_freeciphertext(ct2);
    paillier_freeplaintext(lvd);
    paillier_freeciphertext(lve);

    return 0;
}
