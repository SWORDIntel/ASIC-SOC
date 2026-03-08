
__kernel void signature_scanner(
    __global const char *data,
    __global const char *signatures,
    const int data_len,
    const int sig_len,
    const int sig_count,
    __global int *results)
{
    int gid = get_global_id(0); // Each thread checks one starting position in the data buffer
    
    if (gid > data_len - sig_len) return;

    for (int s = 0; s < sig_count; s++) {
        int match = 1;
        __global const char *current_sig = &signatures[s * sig_len];
        
        for (int i = 0; i < sig_len; i++) {
            if (data[gid + i] != current_sig[i]) {
                match = 0;
                break;
            }
        }
        
        if (match) {
            results[gid] = s + 1; // Mark match with signature ID
        }
    }
}
