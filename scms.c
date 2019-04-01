#include "relic.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#define tmax 1 // 52 = 1 ano; 156 = 3 anos; 1560 = 30 anos
#define cmax 1 // 20 a 40 // Número de certificados válidos no mesmo período de tempo
#define iteracoes 1000       //100  //1000
#define iterdentro 100     //1000 //100

static int start(){
    core_init();
    if  (core_init() != STS_OK){
        core_clean();
        return  1;
    }
    ec_param_set_any();
    return  0;
}

int ep_param_level2() {
	switch (ep_param_get()) {
		case BN_P158:
			return 78;
		case SECG_P160:
		case SECG_K160:
			return 80;
		case NIST_P192:
		case SECG_K192:
			return 96;
		case NIST_P224:
		case SECG_K224:
			return 112;
		case BN_P254:
		case BN_P256:
			return 112;
		case NIST_P256:
		case SECG_K256:
			return 128;
		case B12_P381:
		case BN_P382:
		case SS_P1536:
			return 128;
		case B12_P455:
			return 140;
		case NIST_P384:
			return 192;
		case NIST_P521:
			return 256;
		case BN_P638:
		case B12_P638:
			return 160;
        case CURVE_25519:
            return 128;
	}
	return 0;
}

int cp_ecies_enc2(ec_t r, uint8_t *out, int *out_len, uint8_t *in, int in_len, ec_t q) {
	bn_t k, n, x;
	ec_t p;
	int l, result = STS_OK, size = CEIL(ep_param_level2(), 8);
	uint8_t _x[FC_BYTES + 1], key[2 * size], iv[BC_LEN] = { 0 };

	bn_null(k);
	bn_null(n);
	bn_null(x);
	ec_null(p);

	TRY {
		bn_new(k);
		bn_new(n);
		bn_new(x);
		ec_new(p);

		ec_curve_get_ord(n);
		bn_rand_mod(k, n);

		ec_mul_gen(r, k);
		ec_mul(p, q, k);
		ec_get_x(x, p);
		l = bn_size_bin(x);
		if (bn_bits(x) % 8 == 0) {
			/* Compatibility with BouncyCastle. */
			l = l + 1;
		}
		bn_write_bin(_x, l, x);
		md_kdf2(key, 2 * size, _x, l);
		l = *out_len;
		if (bc_aes_cbc_enc(out, out_len, in, in_len, key, 8 * size, iv)
				!= STS_OK || (*out_len + MD_LEN) > l) {
			result = STS_ERR;
		} else {
			md_hmac(out + *out_len, out, *out_len, key + size, size);
			*out_len += MD_LEN;
		}
	}
	CATCH_ANY {
		result = STS_ERR;
	}
	FINALLY {
		bn_free(k);
		bn_free(n);
		bn_free(x);
		ec_free(p);
	}

	return result;
}

int cp_ecies_dec2(uint8_t *out, int *out_len, ec_t r, uint8_t *in, int in_len, bn_t d) {
	ec_t p;
	bn_t x;
	int l, result = STS_OK, size = CEIL(ep_param_level2(), 8);
	uint8_t _x[FC_BYTES + 1], h[MD_LEN], key[2 * size], iv[BC_LEN] = { 0 };
	bn_null(x);
	ec_null(p);

	TRY {
		bn_new(x);
		ec_new(p);
		ec_mul(p, r, d);
		ec_get_x(x, p);
		l = bn_size_bin(x);
		if (bn_bits(x) % 8 == 0) {
			/* Compatibility with BouncyCastle. */
			l = l + 1;
		}
		bn_write_bin(_x, l, x);
		md_kdf2(key, 2 * size, _x, l);
		md_hmac(h, in, in_len - MD_LEN, key + size, size);
		if (util_cmp_const(h, in + in_len - MD_LEN, MD_LEN)) {
			result = STS_ERR;
		} else {
			if (bc_aes_cbc_dec(out, out_len, in, in_len - MD_LEN, key, 8 * size, iv)
					!= STS_OK) {
				result = STS_ERR;
			}
		}
	}
	CATCH_ANY {
		result = STS_ERR;
	}
	FINALLY {
		bn_free(x);
		ec_free(p);
	}

	return result;
}

uint64_t rdtscp(){
    unsigned int lo,hi;
    __asm__ __volatile__ ("rdtscp" : "=a" (lo), "=d" (hi));
    return ((uint64_t)hi << 32) | lo;
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

    static uint8_t plv_pca[tmax][cmax][8]; for (t = 0; t < tmax; t++) for (c = 0; c < cmax; c++) for (b = 0; b < 8; b++) plv_pca[t][c][b] = 0;
    static uint8_t plv_ra[tmax][cmax][8]; for (t = 0; t < tmax; t++) for (c = 0; c < cmax; c++) for (b = 0; b < 8; b++) plv_pca[t][c][b] = 0;

    //static uint8_t lv_enc[tmax][cmax][768]; for (t = 0; t < tmax; t++) for (c = 0; c < cmax; c++) for (b = 0; b < 768; b++) lv_enc[t][c][b] = 0;
    static uint8_t lv_dec[tmax][cmax][9]; for (t = 0; t < tmax; t++) for (c = 0; c < cmax; c++) for (b = 0; b < 9; b++) lv_dec[t][c][b] = 0;

    uint8_t ent_hash[20]; for (b = 0; b < 20; b++) ent_hash[b] = 0;
    uint8_t sai_hash[32]; for (b = 0; b < 32; b++) sai_hash[b] = 0;

    uint8_t ent_aes[6]; for (b = 0; b < 6; b++) ent_aes[b] = 0;
    uint8_t sai_aes[32]; for (b = 0; b < 32; b++) sai_aes[b] = 0;
    uint8_t vi_aesla1[16]; rand_bytes(vi_aesla1, 16); // VI do AES-128
    uint8_t vi_aesla2[16]; rand_bytes(vi_aesla2, 16); // VI do AES-128
    int tam_saida = 0;

    static uint8_t enc_ecies1[tmax][cmax][48]; for (t = 0; t < tmax; t++) for (c = 0; c < cmax; c++) for (b = 0; b < 48; b++) enc_ecies1[t][c][b] = 0;
    static uint8_t enc_ecies2[tmax][cmax][48]; for (t = 0; t < tmax; t++) for (c = 0; c < cmax; c++) for (b = 0; b < 48; b++) enc_ecies2[t][c][b] = 0;
    static uint8_t dec_ecies1[tmax][cmax][16]; for (t = 0; t < tmax; t++) for (c = 0; c < cmax; c++) for (b = 0; b < 16; b++) dec_ecies1[t][c][b] = 0;
    static uint8_t dec_ecies2[tmax][cmax][16]; for (t = 0; t < tmax; t++) for (c = 0; c < cmax; c++) for (b = 0; b < 16; b++) dec_ecies2[t][c][b] = 0;
    int tam_ecies = 0;
    bn_t ecies_pvt;     bn_null(ecies_pvt);     bn_new(ecies_pvt);
    ec_t ecies_public;  ec_null(ecies_public);  ec_new(ecies_public);   ec_rand(ecies_public);
    static ec_t sai_ecies1[tmax][cmax];    ec_null(sai_ecies1);    ec_new(sai_ecies1);
    static ec_t sai_ecies2[tmax][cmax];    ec_null(sai_ecies2);    ec_new(sai_ecies2);

    bn_t plvpca;        bn_null(plvpca);        bn_new(plvpca);
    bn_t plvra;         bn_null(plvra);         bn_new(plvra);
    bn_t r;             bn_null(r);             bn_new(r);

    int it = 0;
    int it2 = 0;

    // Tempo ciclos

    uint64_t tigen = 0;
    uint64_t tfgen = 0;
    double ttgen = 0;
    double medgen = 0;
    uint64_t vgen[iteracoes]; for (it = 0; it < iteracoes; it++) vgen[it] = 0;
    double vargen = 0;
    double desviogen = 0;

    uint64_t tiencla1 = 0;
    uint64_t tfencla1 = 0;
    double ttencla1 = 0;
    double medencla1 = 0;
    uint64_t vencla1[iteracoes]; for (it = 0; it < iteracoes; it++) vencla1[it] = 0;
    double varencla1 = 0;
    double desvioencla1 = 0;

    uint64_t tiencla2 = 0;
    uint64_t tfencla2 = 0;
    double ttencla2 = 0;
    double medencla2 = 0;
    uint64_t vencla2[iteracoes]; for (it = 0; it < iteracoes; it++) vencla2[it] = 0;
    double varencla2 = 0;
    double desvioencla2 = 0;

    uint64_t tidecla1 = 0;
    uint64_t tfdecla1 = 0;
    double ttdecla1 = 0;
    double meddecla1 = 0;
    uint64_t vdecla1[iteracoes]; for (it = 0; it < iteracoes; it++) vdecla1[it] = 0;
    double vardecla1 = 0;
    double desviodecla1 = 0;

    uint64_t tidecla2 = 0;
    uint64_t tfdecla2 = 0;
    double ttdecla2 = 0;
    double meddecla2 = 0;
    uint64_t vdecla2[iteracoes]; for (it = 0; it < iteracoes; it++) vdecla2[it] = 0;
    double vardecla2 = 0;
    double desviodecla2 = 0;

    // Tempo segundos

    double ttgens = 0;
    double medgens = 0;
    ull_t vgens[iteracoes]; for (it = 0; it < iteracoes; it++) vgens[it] = 0;
    double vargens = 0;
    double desviogens = 0;

    double ttenclas1 = 0;
    double medenclas1 = 0;
    ull_t venclas1[iteracoes]; for (it = 0; it < iteracoes; it++) venclas1[it] = 0;
    double varenclas1 = 0;
    double desvioenclas1 = 0;

    double ttenclas2 = 0;
    double medenclas2 = 0;
    ull_t venclas2[iteracoes]; for (it = 0; it < iteracoes; it++) venclas2[it] = 0;
    double varenclas2 = 0;
    double desvioenclas2 = 0;

    double ttdeclas1 = 0;
    double meddeclas1 = 0;
    ull_t vdeclas1[iteracoes]; for (it = 0; it < iteracoes; it++) vdeclas1[it] = 0;
    double vardeclas1 = 0;
    double desviodeclas1 = 0;

    double ttdeclas2 = 0;
    double meddeclas2 = 0;
    ull_t vdeclas2[iteracoes]; for (it = 0; it < iteracoes; it++) vdeclas2[it] = 0;
    double vardeclas2 = 0;
    double desviodeclas2 = 0;

    FILE *out_file;
    out_file = fopen("saida.txt", "wb");
    fprintf(out_file, "tmax = %d\ncmax = %d\niteracoes = %d\n\n", tmax, cmax, iteracoes);

    // Fim declaração

    for (it = 0; it < iteracoes; it++){

        //PCA

        // Início Bench Gen
        medgen = 0;
        medgens = 0;
        medencla1 = 0;
        medenclas1 = 0;
        medencla2 = 0;
        medenclas2 = 0;
        meddecla1 = 0;
        meddeclas1 = 0;
        meddecla2 = 0;
        meddeclas2 = 0;

        for (it2 = 0; it2 < iterdentro; it2++){
            printf("it = %d, itd = %d\n", it, it2);

            //Inicio Bench Gen
            bench_reset();
            bench_before();
            tigen = rdtscp();

            // Geração de chaves ECIES
            cp_ecies_gen(ecies_pvt, ecies_public);

            // Fim Bench Gen
            tfgen = rdtscp();
            medgen += tfgen - tigen;
            bench_after();
            bench_compute(1);
            medgens += bench_total();

            // LA1

            // Início Bench Enc LA1
            bench_reset();
            bench_before();
            tiencla1 = rdtscp();

            // Armazena entrada do ID da LA1 na entrada do hash
            memcpy(ent_hash, pca_id, 4);

            // Para cada período de tempo
            for (t = 0; t < tmax; t++){
                // Cálculo das Linkage Seeds usando SHA-256

                // Armazena a Linkage Seed anterior na entrada do hash concatenando com o ID da LA1
                memcpy(ent_hash+4, ls_pca[t], 16);

                // SHA-256
                md_map_sh256(sai_hash, ent_hash, 20);

                // Armazena os 16 primeiros bytes de saída do hash
                memcpy(ls_pca[t+1], sai_hash, 16);

                // Cálculo PLV usando AES-128

                // Armazena o ID da LA1 na entrada do AES-128
                memcpy(ent_aes, pca_id, 4);

                // Para cada certificado válido em um mesmo período de tempo
                for(c = 0; c < cmax; c++){

                    // Concatena o valor de c na entrada do AES-128
                    ent_aes[4] = c;

                    tam_saida = 32;

                    // Encriptação AES-128
                    bc_aes_cbc_enc(sai_aes, &tam_saida, ent_aes, 6, ls_pca[t+1], 128, vi_aesla1);

                    //printf("plv_la1[%d][%d] = ", t, c); for (b = 0; b < 8; b++) printf("%02X", sai_aes[b]); printf("\n");

                    memcpy(plv_pca[t][c], sai_aes, 8);

                    // Encriptação ECIES LA1

                    tam_ecies = 48;

                    cp_ecies_enc2(sai_ecies1[t][c], enc_ecies1[t][c], &tam_ecies, plv_pca[t][c], 8, ecies_public);

                    //printf("enc_ecies1[%d][%d] = ", t, c); for (b = 0; b < 48; b++) printf("%02X", enc_ecies1[t][c][b]); printf("\n");

                }
            }

            // Fim Bench Enc LA1

            tfencla1 = rdtscp();
            medencla1 += tfencla1 - tiencla1;
            bench_after();
            bench_compute(1);
            medenclas1 += bench_total();

            // LA2

            // Inicio Bench Enc LA2
            bench_reset();
            bench_before();
            tiencla2 = rdtscp();

            // Armazena entrada do ID da LA2 na entrada do hash
            memcpy(ent_hash, ra_id, 4);

            // Para cada período de tempo
            for (t = 0; t < tmax; t++){
                // Cálculo das Linkage Seeds usando SHA-256

                // Armazena a Linkage Seed anterior na entrada do hash concatenando com o ID da LA2
                memcpy(ent_hash+4, ls_ra[t], 16);

                // SHA-256
                md_map_sh256(sai_hash, ent_hash, 20);

                // Armazena os 16 primeiros bytes de saída do hash
                memcpy(ls_ra[t+1], sai_hash, 16);

                // Cálculo PLV usando AES-128

                // Armazena o ID da LA2 na entrada do AES-128
                memcpy(ent_aes, ra_id, 4);

                // Para cada certificado válido em um mesmo período de tempo
                for(c = 0; c < cmax; c++){
                    // Concatena o valor de c na entrada do AES-128
                    ent_aes[4] = c;

                    tam_saida = 32;

                    // Encriptação AES-128
                    bc_aes_cbc_enc(sai_aes, &tam_saida, ent_aes, 6, ls_ra[t+1], 128, vi_aesla2);

                    //printf("plv_la2[%d][%d] = ", t, c); for (b = 0; b < 8; b++) printf("%02X", sai_aes[b]); printf("\n");

                    memcpy(plv_ra[t][c], sai_aes, 8);

                    // Encriptação ECIES LA2

                    tam_ecies = 48;

                    cp_ecies_enc2(sai_ecies2[t][c], enc_ecies2[t][c], &tam_ecies, plv_ra[t][c], 8, ecies_public);

                    //printf("enc_ecies2[%d][%d] = ", t, c); for (b = 0; b < 48; b++) printf("%02X", enc_ecies2[t][c][b]); printf("\n");

                }
            }

            // Fim Bench Enc LA2

            tfencla2 = rdtscp();
            medencla2 += tfencla2 - tiencla2;
            bench_after();
            bench_compute(1);
            medenclas2 += bench_total();

            // PCA

            // Início Bench Dec LA1
            bench_reset();
            bench_before();
            tidecla1 = rdtscp();

            for (t = 0; t < tmax; t++){
                for(c = 0; c < cmax; c++){
                    //Decriptação
                    tam_ecies = 16;
                    cp_ecies_dec2(dec_ecies1[t][c], &tam_ecies, sai_ecies1[t][c], enc_ecies1[t][c], 48, ecies_pvt);

                    //printf("dec_ecies1[%d][%d] = ", t, c); for(b = 0; b < 8; b++) printf("%02X", dec_ecies1[t][c][b]); printf("\n");
                }
            }

            // Fim Bench Dec LA1

            tfdecla1 = rdtscp();
            meddecla1 += tfdecla1 - tidecla1;
            bench_after();
            bench_compute(1);
            meddeclas1 += bench_total();

            // Início Bench Dec LA2
            bench_reset();
            bench_before();
            tidecla2 = rdtscp();

            for (t = 0; t < tmax; t++){
                for(c = 0; c < cmax; c++){
                    //Decriptação
                    tam_ecies = 16;
                    cp_ecies_dec2(dec_ecies2[t][c], &tam_ecies, sai_ecies2[t][c], enc_ecies2[t][c], 48, ecies_pvt);

                    //printf("dec_ecies2[%d][%d] = ", t, c); for(b = 0; b < 8; b++) printf("%02X", dec_ecies2[t][c][b]); printf("\n");
                }
            }
            // Fim Bench Dec LA2

            tfdecla2 = rdtscp();
            meddecla2 += tfdecla2 - tidecla2;
            bench_after();
            bench_compute(1);
            meddeclas2 += bench_total();


            // Cálculo dos Linkage Values
            for (t = 0; t < tmax; t++){
                for(c = 0; c < cmax; c++){

                    bn_read_bin(plvpca, dec_ecies1[t][c], 8);
                    bn_read_bin(plvra, dec_ecies2[t][c], 8);

                    //bn_mul(m, plvpca, plvra);
                    //bn_mod(r, m, n2);
                    bn_add(r, plvpca, plvra);

                    bn_write_bin(lv_dec[t][c], 9, r);

                    //printf("lv_dec[%d][%d] = ", t, c); for(b = 0; b < 9; b++) printf("%02X", lv_dec[t][c][b]); printf("\n");

                }
            }
        }// fim loop it2

        // Medias
        medgen /= (double)iterdentro;
        medgens /= (double)iterdentro;
        vgens[it] = medgens;
        ttgens += vgens[it];
        vgen[it] = medgen;
        ttgen += vgen[it];

        medencla1 /= (double)iterdentro;
        medenclas1 /= (double)iterdentro;
        venclas1[it] = medenclas1;
        ttenclas1 += venclas1[it];
        vencla1[it] = medencla1;
        ttencla1 += vencla1[it];

        medencla2 /= (double)iterdentro;
        medenclas2 /= (double)iterdentro;
        venclas2[it] = medenclas2;
        ttenclas2 += venclas2[it];
        vencla2[it] = medencla2;
        ttencla2 += vencla2[it];

        meddecla1 /= (double)iterdentro;
        meddeclas1 /= (double)iterdentro;
        vdeclas1[it] = meddeclas1;
        ttdeclas1 += vdeclas1[it];
        vdecla1[it] = meddecla1;
        ttdecla1 += vdecla1[it];

        meddecla2 /= (double)iterdentro;
        meddeclas2 /= (double)iterdentro;
        vdeclas2[it] = meddeclas2;
        ttdeclas2 += vdeclas2[it];
        vdecla2[it] = meddecla2;
        ttdecla2 += vdecla2[it];

        fprintf(out_file,"it = %d\n", it);
        fprintf(out_file, "Tempo Gen (Cyc)     = %lu\n", vgen[it]);    fprintf(out_file, "Tempo Gen (NSec)     = %llu\n", vgens[it]);
        fprintf(out_file, "Tempo Enc LA1 (Cyc) = %lu\n", vencla1[it]); fprintf(out_file, "Tempo Enc LA1 (NSec) = %llu\n", venclas1[it]);
        fprintf(out_file, "Tempo Enc LA2 (Cyc) = %lu\n", vencla2[it]); fprintf(out_file, "Tempo Enc LA2 (NSec) = %llu\n", venclas2[it]);
        fprintf(out_file, "Tempo Dec LA1 (Cyc) = %lu\n", vdecla1[it]); fprintf(out_file, "Tempo Dec LA1 (NSec) = %llu\n", vdeclas1[it]);
        fprintf(out_file, "Tempo Dec LA2 (Cyc) = %lu\n", vdecla2[it]); fprintf(out_file, "Tempo Dec LA2 (NSec) = %llu\n", vdeclas2[it]);
    }// fim loop it1

    ttgen /= (double)iteracoes;
    ttencla1 /= (double)iteracoes;
    ttencla2 /= (double)iteracoes;
    ttdecla1 /= (double)iteracoes;
    ttdecla2 /= (double)iteracoes;

    ttgens /= (double)iteracoes;
    ttenclas1 /= (double)iteracoes;
    ttenclas2 /= (double)iteracoes;
    ttdeclas1 /= (double)iteracoes;
    ttdeclas2 /= (double)iteracoes;

    fprintf(out_file, "\nCiclos\n");
    fprintf(out_file, "Media Gen     = %lf\n", ttgen);
    fprintf(out_file, "Media Enc LA1 = %lf\n", ttencla1);
    fprintf(out_file, "Media Enc LA2 = %lf\n", ttencla2);
    fprintf(out_file, "Media Dec LA1 = %lf\n", ttdecla1);
    fprintf(out_file, "Media Dec LA2 = %lf\n", ttdecla2);

    fprintf(out_file, "\nNano Segundos\n");
    fprintf(out_file, "Media Gen     = %lf\n", ttgens);
    fprintf(out_file, "Media Enc LA1 = %lf\n", ttenclas1);
    fprintf(out_file, "Media Enc LA2 = %lf\n", ttenclas2);
    fprintf(out_file, "Media Dec LA1 = %lf\n", ttdeclas1);
    fprintf(out_file, "Media Dec LA2 = %lf\n", ttdeclas2);

    for (it = 0; it < iteracoes; it++){
        vargen += (vgen[it] - ttgen)*(vgen[it] - ttgen);
        varencla1 += (vencla1[it] - ttencla1)*(vencla1[it] - ttencla1);
        varencla2 += (vencla2[it] - ttencla2)*(vencla2[it] - ttencla2);
        vardecla1 += (vdecla1[it] - ttdecla1)*(vdecla1[it] - ttdecla1);
        vardecla2 += (vdecla2[it] - ttdecla2)*(vdecla2[it] - ttdecla2);

        vargens += (vgens[it] - ttgens)*(vgens[it] - ttgens);
        varenclas1 += (venclas1[it] - ttenclas1)*(venclas1[it] - ttenclas1);
        varenclas2 += (venclas2[it] - ttenclas2)*(venclas2[it] - ttenclas2);
        vardeclas1 += (vdeclas1[it] - ttdeclas1)*(vdeclas1[it] - ttdeclas1);
        vardeclas2 += (vdeclas2[it] - ttdeclas2)*(vdeclas2[it] - ttdeclas2);
    }

    vargen /= (double)iteracoes;
    varencla1 /= (double)iteracoes;
    varencla2 /= (double)iteracoes;
    vardecla1 /= (double)iteracoes;
    vardecla2 /= (double)iteracoes;

    vargens /= (double)iteracoes;
    varenclas1 /= (double)iteracoes;
    varenclas2 /= (double)iteracoes;
    vardeclas1 /= (double)iteracoes;
    vardeclas2 /= (double)iteracoes;

    desviogen = sqrt(vargen);
    desvioencla1 = sqrt(varencla1);
    desvioencla2 = sqrt(varencla2);
    desviodecla1 = sqrt(vardecla1);
    desviodecla2 = sqrt(vardecla2);

    desviogens = sqrt(vargens);
    desvioenclas1 = sqrt(varenclas1);
    desvioenclas2 = sqrt(varenclas2);
    desviodeclas1 = sqrt(vardeclas1);
    desviodeclas2 = sqrt(vardeclas2);

    fprintf(out_file, "\nCiclos\n");
    fprintf(out_file, "Desvio Padrao Gen     = %lf\n", desviogen);
    fprintf(out_file, "Desvio Padrao Enc LA1 = %lf\n", desvioencla1);
    fprintf(out_file, "Desvio Padrao Enc LA2 = %lf\n", desvioencla2);
    fprintf(out_file, "Desvio Padrao Dec LA1 = %lf\n", desviodecla1);
    fprintf(out_file, "Desvio Padrao Dec LA2 = %lf\n", desviodecla2);

    fprintf(out_file, "\nNano Segundos\n");
    fprintf(out_file, "Desvio Padrao Gen     = %lf\n", desviogens);
    fprintf(out_file, "Desvio Padrao Enc LA1 = %lf\n", desvioenclas1);
    fprintf(out_file, "Desvio Padrao Enc LA2 = %lf\n", desvioenclas2);
    fprintf(out_file, "Desvio Padrao Dec LA1 = %lf\n", desviodeclas1);
    fprintf(out_file, "Desvio Padrao Dec LA2 = %lf\n", desviodeclas2);

    fflush(out_file);
    fclose(out_file);

    printf("ok\n");

    ec_free(sai_ecies1);
    ec_free(sai_ecies2);
    ec_free(ecies_public);
    bn_free(ecies_pvt);
    bn_free(plvpca);
    bn_free(plvra);
    bn_free(r);

    return 0;
}
