@php
    $total = max($fail + $warn + $pass, 1);

    $items = [
        [
            'label' => 'FAIL',
            'count' => $fail,
            'description' => 'Critical findings that need immediate action.',
            'percent' => round(($fail / $total) * 100),
            'card' => 'border-danger-200 bg-linear-to-br from-danger-50 to-white dark:border-danger-500/30 dark:from-danger-500/15 dark:to-transparent',
            'pill' => 'bg-danger-100 text-danger-700 ring-danger-200 dark:bg-danger-500/15 dark:text-danger-200 dark:ring-danger-500/30',
            'value' => 'text-danger-700 dark:text-danger-200',
            'track' => 'bg-danger-100 dark:bg-danger-500/15',
            'bar' => 'bg-danger-500',
        ],
        [
            'label' => 'WARN',
            'count' => $warn,
            'description' => 'Items that should be reviewed soon.',
            'percent' => round(($warn / $total) * 100),
            'card' => 'border-warning-200 bg-linear-to-br from-warning-50 to-white dark:border-warning-500/30 dark:from-warning-500/15 dark:to-transparent',
            'pill' => 'bg-warning-100 text-warning-700 ring-warning-200 dark:bg-warning-500/15 dark:text-warning-200 dark:ring-warning-500/30',
            'value' => 'text-warning-700 dark:text-warning-200',
            'track' => 'bg-warning-100 dark:bg-warning-500/15',
            'bar' => 'bg-warning-500',
        ],
        [
            'label' => 'PASS',
            'count' => $pass,
            'description' => 'Checks that are currently compliant.',
            'percent' => round(($pass / $total) * 100),
            'card' => 'border-success-200 bg-linear-to-br from-success-50 to-white dark:border-success-500/30 dark:from-success-500/15 dark:to-transparent',
            'pill' => 'bg-success-100 text-success-700 ring-success-200 dark:bg-success-500/15 dark:text-success-200 dark:ring-success-500/30',
            'value' => 'text-success-700 dark:text-success-200',
            'track' => 'bg-success-100 dark:bg-success-500/15',
            'bar' => 'bg-success-500',
        ],
    ];
@endphp

<x-filament::widget>
    <x-filament::section heading="Severity Breakdown">
        <div class="space-y-4">
            <div class="rounded-2xl border border-gray-200 bg-linear-to-r from-gray-50 to-white px-5 py-4 dark:border-white/10 dark:from-white/5 dark:to-transparent">
                <div class="flex items-center justify-between gap-4">
                    <div>
                        <div class="text-xs font-medium uppercase tracking-[0.22em] text-gray-500 dark:text-gray-400">Findings Snapshot</div>
                        <div class="mt-2 text-3xl font-semibold text-gray-950 dark:text-white">{{ $fail + $warn + $pass }}</div>
                        <div class="mt-1 text-sm text-gray-600 dark:text-gray-300">Total filtered findings across all active severities.</div>
                    </div>

                    <div class="grid grid-cols-3 gap-2 text-center">
                        <div class="rounded-xl bg-white px-3 py-2 shadow-xs ring-1 ring-gray-200 dark:bg-white/5 dark:ring-white/10">
                            <div class="text-xs uppercase tracking-[0.16em] text-gray-500 dark:text-gray-400">Fail</div>
                            <div class="mt-1 text-lg font-semibold text-danger-600 dark:text-danger-300">{{ $fail }}</div>
                        </div>
                        <div class="rounded-xl bg-white px-3 py-2 shadow-xs ring-1 ring-gray-200 dark:bg-white/5 dark:ring-white/10">
                            <div class="text-xs uppercase tracking-[0.16em] text-gray-500 dark:text-gray-400">Warn</div>
                            <div class="mt-1 text-lg font-semibold text-warning-600 dark:text-warning-300">{{ $warn }}</div>
                        </div>
                        <div class="rounded-xl bg-white px-3 py-2 shadow-xs ring-1 ring-gray-200 dark:bg-white/5 dark:ring-white/10">
                            <div class="text-xs uppercase tracking-[0.16em] text-gray-500 dark:text-gray-400">Pass</div>
                            <div class="mt-1 text-lg font-semibold text-success-600 dark:text-success-300">{{ $pass }}</div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="grid gap-4">
                @foreach ($items as $item)
                    <div class="rounded-2xl border px-4 py-4 shadow-xs {{ $item['card'] }}">
                        <div class="flex items-start justify-between gap-4">
                            <div class="min-w-0">
                                <div class="inline-flex items-center rounded-full px-2.5 py-1 text-[11px] font-semibold uppercase tracking-[0.22em] ring-1 ring-inset {{ $item['pill'] }}">
                                    {{ $item['label'] }}
                                </div>
                                <div class="mt-3 text-sm leading-6 text-gray-600 dark:text-gray-300">{{ $item['description'] }}</div>
                            </div>

                            <div class="text-right">
                                <div class="text-4xl font-semibold leading-none {{ $item['value'] }}">{{ $item['count'] }}</div>
                                <div class="mt-2 text-xs font-medium uppercase tracking-[0.18em] text-gray-500 dark:text-gray-400">{{ $item['percent'] }}%</div>
                            </div>
                        </div>

                        <div class="mt-4">
                            <div class="h-2 w-full overflow-hidden rounded-full {{ $item['track'] }}">
                                <div
                                    class="h-full rounded-full {{ $item['bar'] }}"
                                    style="width: {{ $item['percent'] }}%;"
                                ></div>
                            </div>
                        </div>
                    </div>
                @endforeach
            </div>
        </div>
    </x-filament::section>
</x-filament::widget>
